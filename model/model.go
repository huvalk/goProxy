package model

type RequestToSave struct {
	Host      string
	Url       string
	Headers   Params
	URLParams Params
	Body      string
	Proto     string
	Method    string
}

type Params map[string][]string
