package dcerpc

import (
	"context"
	"fmt"
	"github.com/oiweiwei/go-msrpc/extra"
	"github.com/oiweiwei/go-msrpc/ssp/spnego"
	"sync"
	"time"
)

func (c *transport) BindSync(ctx context.Context, opts ...Option) (Conn, error) {

	if err := c.HasErr(); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	if conn, ok := HasNoBind(opts); ok {
		return conn, nil
	}

	if c.IsBinded() {
		return c.AlterContext(ctx, opts...)
	}

	c.callMu.Lock()
	defer c.callMu.Unlock()

	o, err := ParseOptions(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("bind: parse options: %w", err)
	}

	c.logger = o.Logger

	call, err := c.makeCall(ctx, noCopy{})
	if err != nil {
		return nil, fmt.Errorf("bind: allocate channel: %w", err)
	}

	// set/override the settings group id if association is non-zero.
	c.settings.GroupID = o.Group.SetID(c.settings.GroupID)

	pkt := &Packet{
		Header: Header{
			PacketFlags: PacketFlagFirstFrag | PacketFlagLastFrag | PacketFlagConcMPX | o.Security.RequestHeaderSign,
		},
		PDU: &Bind{
			MaxXmitFrag:  uint16(c.settings.MaxXmitFrag),
			MaxRecvFrag:  uint16(c.settings.MaxRecvFrag),
			AssocGroupID: uint32(c.settings.GroupID),
			ContextList:  c.PresentationsToContextList(o.Presentations, o.TransferSyntaxes),
		},
		SecurityTrailer: o.Security.SecurityTrailer(),
	}
	// set auth data.

	clientNegByte, ok := ctx.Value(extra.NEG_TOKEN).([]byte)
	if ok {
		o.Security.ctx = context.WithValue(o.Security.ctx, extra.NEG_TOKEN, clientNegByte)
	}

	if pkt.AuthData, err = o.Security.Init(ctx, nil); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	// write bind pdu.
	if err = c.WritePacket(ctx, call, pkt); err != nil {
		return nil, fmt.Errorf("bind: write packet: %w", err)
	}
	// read bind response (bind-ack, bind-nak).
	if pkt, err = c.ReadPacket(ctx, call); err != nil {
		return nil, fmt.Errorf("bind: read packet: %w", err)
	}

	switch pdu := (interface{})(pkt.PDU).(type) {

	case *BindAck:

		if c.settings.MaxRecvFrag != int(pdu.MaxRecvFrag) {
			// reset buffered connector.
			c.cc = c.cc.(*BufferedConn).Resized(int(pdu.MaxRecvFrag))
		}

		sz := c.settings.FragmentSize()

		// save retrieved parameters.
		c.settings.MaxRecvFrag = int(pdu.MaxRecvFrag)
		c.settings.MaxXmitFrag = int(pdu.MaxXmitFrag)
		c.settings.GroupID = int(pdu.AssocGroupID)
		c.settings.SecondaryAddr = pdu.PortSpec

		// set the group id for the association.
		o.Group.SetID(int(pdu.AssocGroupID))

		if sz != c.settings.FragmentSize() {
			c.tx, c.rx = make([]byte, c.settings.FragmentSize()), make([]byte, c.settings.FragmentSize())
		}

		// save negotiated header sign parameter.
		o.Security.SignHeader = pkt.Header.PacketFlags.IsSet(PacketFlagSupportHeaderSign)
		c.settings.Multiplexing = pkt.Header.PacketFlags.IsSet(PacketFlagConcMPX)

		feature := c.PresentationFromContextList(o.Presentations, pdu.ResultList)
		c.settings.KeepConnOpenOnOrphaned = feature.KeepConnOpenOnOrphaned()
		c.settings.SecurityContextMultiplexing = feature.SecurityContextMultiplexing()

		c.logger.Debug().EmbedObject(c.settings).Msg("negotiated_features")

	case *BindNak:
		return nil, c.asyncClose(ctx, fmt.Errorf("bind: %w", pdu))
	default:
		return nil, c.asyncClose(ctx, fmt.Errorf("bind: unexpected response: %s", pkt.Header.PacketType))
	}
	var clientChallenge []byte

	for !o.Security.Established() {
		// alter context until the security context is established.
		pkt = &Packet{
			Header: Header{
				PacketFlags: PacketFlagFirstFrag | PacketFlagLastFrag | o.Security.RequestHeaderSign,
			},
			PDU: &AlterContext{
				ContextList: c.PresentationsToContextList(o.Presentations, o.TransferSyntaxes),
			},
			SecurityTrailer: o.Security.SecurityTrailer(),
			AuthData:        pkt.AuthData,
		}

		//这里需要获取到挑战值：

		serverChan, okServer := ctx.Value(extra.SERVER_CHALLENGE_KEY).(extra.ServerChallengeChannel)
		clientChan, okClient := ctx.Value(extra.CLIENT_CHALLENGE_KEY).(extra.ClientChallengeChannel)
		useSpenGo, okUse := ctx.Value(extra.SPNEGO).(bool)
		if okServer && okClient && clientChallenge == nil {

			if okUse && useSpenGo {
				resp := &spnego.NegTokenResp{}
				err := resp.Unmarshal(context.Background(), pkt.AuthData)
				if err != nil {
					return nil, c.asyncClose(ctx, fmt.Errorf("resp反序列化失败: %w", err))
				}
				serverChan <- resp.ResponseToken
			} else {
				serverChan <- pkt.AuthData
			}

			t := time.After(10 * time.Second)
			//wait客户端:
		loop:
			for {
				select {
				case <-t:
					return nil, c.asyncClose(ctx, fmt.Errorf("等待客户端clientKey超时: %w", err))
				case clientChallenge = <-clientChan:
					break loop
				default:
				}
			}
			fmt.Println("先执行了 " + string(clientChallenge))
			o.Security.ctx = context.WithValue(o.Security.ctx, "clientBytes", clientChallenge)
		}

		if pkt.AuthData, err = o.Security.Init(ctx, pkt.AuthData); err != nil {
			return nil, c.asyncClose(ctx, err)
		}
		// context has been successfully established.
		if len(pkt.AuthData) == 0 && o.Security.Established() {
			break
		}

		call, err := c.makeCall(ctx, noCopy{})
		if err != nil {
			return nil, c.asyncClose(ctx, fmt.Errorf("bind: alter context: allocate channel: %w", err))
		}

		if o.Security.Type.Legs() == LegsOdd && pkt.AuthData == nil {
			// replace type with auth3.
			pkt.PDU = &Auth3{}
			// write auth3 pdu.
			if err = c.WritePacket(ctx, call, pkt); err != nil {
				return nil, fmt.Errorf("bind: alter context: auth3: write packet: %w", err)
			}

			// no response is assumed.
			break
		}
		// write alter_context request.
		if err = c.WritePacket(ctx, call, pkt); err != nil {
			return nil, fmt.Errorf("bind: alter context: write packet: %w", err)
		}
		if pkt.AuthData != nil {
			//bufConn := c.cc.(*BufferedConn)
			//b := make([]byte, 2048)
			//n, _ := bufConn.RawConn.Read(b)
			//fmt.Println("!!!!!!!!!!!" + hex.EncodeToString(b[:n]))

			if pkt, err = c.ReadPacket(ctx, call); err != nil {
				return nil, fmt.Errorf("bind: alter context: read packet: %w", err)
			}
		} else {
			// read alter_context response.

			if pkt, err = c.ReadPacket(ctx, call); err != nil {
				return nil, fmt.Errorf("bind: alter context: read packet: %w", err)
			}
		}

		// check response.
		if _, ok := pkt.PDU.(*AlterContextResponse); !ok {
			return nil, c.asyncClose(ctx, fmt.Errorf("bind: alter context: unexpected response: %s", pkt.Header.PacketType))
		}

		o.Security.SignHeader = pkt.Header.PacketFlags.IsSet(PacketFlagSupportHeaderSign)
	}

	if o.IsNewSecurity && o.Security.Level >= AuthLevelConnect {
		// increment security context count for multiplexing.
		c.settings.SecurityContextCount++
	}

	ctx, c.close = context.WithCancel(ctx)
	c.closeWait = new(sync.WaitGroup)

	c.Binded()

	// run receiver.
	c.closeWait.Add(1)
	go func() {
		defer c.closeWait.Done()
		if err := c.recvLoop(ctx); err != nil {
			c.WithErr(err)
			c.logger.Info().Err(err).Msg("receiver terminated")
		}
	}()

	// run sender.
	c.closeWait.Add(1)
	go func() {
		defer c.closeWait.Done()
		if err := c.sendLoop(ctx); err != nil {
			c.WithErr(err)
			c.logger.Info().Err(err).Msg("sender terminated")
		}
	}()

	return c.makeConn(o), nil
}
