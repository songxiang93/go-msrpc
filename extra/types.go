package extra

type ServerChallengeChannel chan []byte
type ClientChallengeChannel chan []byte

const SERVER_CHALLENGE_KEY = "serverChallenge"
const CLIENT_CHALLENGE_KEY = "clientChallenge"
const NEG_TOKEN = "negToken"
const SPNEGO = "spnego"
