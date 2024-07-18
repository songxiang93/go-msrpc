package midl

// keyword.go contains reserved keywords and keyword to string
// mappings.

var (
	NameTok = map[string]int{}

	TokName = map[int]string{
		FLOAT:                      "float",
		DOUBLE:                     "double",
		UNSIGNED:                   "unsigned",
		SIGNED:                     "signed",
		LONG:                       "long",
		SHORT:                      "short",
		SMALL:                      "small",
		INT:                        "int",
		CHAR:                       "char",
		BOOLEAN:                    "boolean",
		BYTE:                       "byte",
		VOID:                       "void",
		HYPER:                      "hyper",
		HANDLE_T:                   "handle_t",
		ERROR_STATUS_T:             "error_status_t",
		ISO_LATIN_1:                "ISO_LATIN_1",
		ISO_MULTILINGUAL:           "ISO_MULTILINGUAL",
		ISO_UCS:                    "ISO_UCS",
		STRUCT:                     "struct",
		FIRST_IS:                   "first_is",
		LAST_IS:                    "last_is",
		LENGTH_IS:                  "length_is",
		MIN_IS:                     "min_is",
		MAX_IS:                     "max_is",
		SIZE_IS:                    "size_is",
		SWITCH_IS:                  "switch_is",
		IGNORE:                     "ignore",
		USAGE_STRING:               "string",
		USAGE_CONTEXT_HANDLE:       "context_handle",
		FORMAT:                     "format",
		FORMAT_NULL_TERMINATED:     "null_terminated",
		FORMAT_UTF8:                "utf8",
		FORMAT_MULTI_SIZE:          "multi_size",
		FORMAT_RUNE:                "rune",
		FORMAT_HEX:                 "hex",
		POINTER_REF:                "ref",
		POINTER_UNIQUE:             "unique",
		POINTER_PTR:                "ptr",
		NULL:                       "NULL",
		TRUE:                       "TRUE",
		FALSE:                      "FALSE",
		IN:                         "in",
		OUT:                        "out",
		ENUM:                       "enum",
		PIPE:                       "pipe",
		UNION:                      "union",
		SWITCH:                     "switch",
		CASE:                       "case",
		DEFAULT:                    "default",
		SOURCE:                     "source",
		ANNOTATION:                 "annotation",
		CALL_AS:                    "call_as",
		WIRE_MARSHAL:               "wire_marshal",
		PUBLIC:                     "public",
		METHODS:                    "methods",
		PROPERTIES:                 "properties",
		LIBRARY:                    "library",
		SAFEARRAY:                  "safearray",
		PAD:                        "pad",
		GOEXT_LAYOUT:               "goext_layout",
		OPTIONAL:                   "optional",
		COCLASS:                    "coclass",
		SWITCH_TYPE:                "switch_type",
		TRANSMIT_AS:                "transmit_as",
		HANDLE:                     "handle",
		IMPORT:                     "import",
		TYPEDEF:                    "typedef",
		CONST:                      "const",
		IDEMPOTENT:                 "idempotent",
		BROADCAST:                  "broadcast",
		MAYBE:                      "maybe",
		REFLECT_DELETIONS:          "reflect_deletions",
		UUID:                       "uuid",
		INTERFACE:                  "interface",
		ENDPOINT:                   "endpoint",
		VERSION:                    "version",
		EXCEPTIONS:                 "exceptions",
		LOCAL:                      "local",
		POINTER_DEFAULT:            "pointer_default",
		WCHAR_T:                    "wchar_t",
		INT8:                       "__int8",
		INT16:                      "__int16",
		INT32:                      "__int32",
		INT64:                      "__int64",
		INT3264:                    "__int3264",
		RANGE:                      "range",
		MS_UNION:                   "ms_union",
		CALLBACK:                   "callback",
		HELP_STRING:                "helpstring",
		ID:                         "id",
		PROPGET:                    "propget",
		PROPPUT:                    "propput",
		PROPPUTREF:                 "propputref",
		DUAL:                       "dual",
		HIDDEN:                     "hidden",
		NONEXTENSIBLE:              "nonextensible",
		RESTRICTED:                 "restricted",
		DEFAULT_VALUE:              "defaultvalue",
		ODL:                        "odl",
		OLEAUTOMATION:              "oleautomation",
		OBJECT:                     "object",
		APPOBJECT:                  "appobject",
		DISPINTERFACE:              "dispinterface",
		V1_ENUM:                    "v1_enum",
		ACS_BYTE_COUNT:             "byte_count",
		STRICT_CONTEXT_HANDLE:      "strict_context_handle",
		TYPE_STRICT_CONTEXT_HANDLE: "type_strict_context_handle",
		DISABLE_CONSISTENCY_CHECK:  "disable_consistency_check",
		SIZEOF:                     "sizeof",
		PRAGMA_CPP_QUOTE:           "cpp_quote",
		RETVAL:                     "retval",
		IID_IS:                     "iid_is",
	}

	SQBReservedTok = map[int]struct{}{
		ANNOTATION:                 {},
		APPOBJECT:                  {},
		BROADCAST:                  {},
		CALL_AS:                    {},
		CALLBACK:                   {},
		DEFAULT_VALUE:              {},
		DISABLE_CONSISTENCY_CHECK:  {},
		ENDPOINT:                   {},
		FIRST_IS:                   {},
		HANDLE:                     {},
		HELP_STRING:                {},
		HIDDEN:                     {},
		ID:                         {},
		IGNORE:                     {},
		IDEMPOTENT:                 {},
		IID_IS:                     {},
		IN:                         {},
		LAST_IS:                    {},
		LENGTH_IS:                  {},
		LOCAL:                      {},
		MAX_IS:                     {},
		MAYBE:                      {},
		MIN_IS:                     {},
		MS_UNION:                   {},
		OBJECT:                     {},
		ODL:                        {},
		OLEAUTOMATION:              {},
		OPTIONAL:                   {},
		OUT:                        {},
		POINTER_DEFAULT:            {},
		PROPGET:                    {},
		PROPPUT:                    {},
		PROPPUTREF:                 {},
		POINTER_PTR:                {},
		PUBLIC:                     {},
		RANGE:                      {},
		POINTER_REF:                {},
		RETVAL:                     {},
		SIZE_IS:                    {},
		SOURCE:                     {},
		STRICT_CONTEXT_HANDLE:      {},
		USAGE_STRING:               {},
		USAGE_CONTEXT_HANDLE:       {},
		FORMAT:                     {},
		FORMAT_UTF8:                {},
		FORMAT_NULL_TERMINATED:     {},
		FORMAT_MULTI_SIZE:          {},
		FORMAT_RUNE:                {},
		FORMAT_HEX:                 {},
		SWITCH_IS:                  {},
		SWITCH_TYPE:                {},
		TRANSMIT_AS:                {},
		TYPE_STRICT_CONTEXT_HANDLE: {},
		POINTER_UNIQUE:             {},
		UUID:                       {},
		VERSION:                    {},
		WIRE_MARSHAL:               {},
		PAD:                        {},
		GOEXT_LAYOUT:               {},
		SAFEARRAY:                  {},
	}

	ReservedTok = map[int]struct{}{
		SIZEOF:           {},
		PRAGMA_CPP_QUOTE: {},
		FLOAT:            {},
		DOUBLE:           {},
		HYPER:            {},
		UNSIGNED:         {},
		SIGNED:           {},
		LONG:             {},
		SHORT:            {},
		SMALL:            {},
		INT:              {},
		INT8:             {},
		INT16:            {},
		INT32:            {},
		INT64:            {},
		INT3264:          {},
		CHAR:             {},
		WCHAR_T:          {},
		BOOLEAN:          {},
		BYTE:             {},
		VOID:             {},
		HANDLE_T:         {},
		ERROR_STATUS_T:   {},
		ISO_LATIN_1:      {},
		ISO_MULTILINGUAL: {},
		ISO_UCS:          {},
		STRUCT:           {},
		CONST:            {},
		NULL:             {},
		TRUE:             {},
		FALSE:            {},
		ENUM:             {},
		PIPE:             {},
		UNION:            {},
		SWITCH:           {},
		CASE:             {},
		DEFAULT:          {},
		IMPORT:           {},
		TYPEDEF:          {},
		INTERFACE:        {},
		COCLASS:          {},
		DISPINTERFACE:    {},
	}
)

func init() {
	// XXX: fill in NameTok map.
	for k, v := range TokName {
		NameTok[v] = k
	}

	for tok := range ReservedTok {
		SQBReservedTok[tok] = struct{}{}
	}
}
