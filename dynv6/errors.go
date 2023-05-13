package dynv6

type error422 struct {
	errorinfo
	Fields []errorinfo `json:"fields"`
}

type errorinfo struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}
