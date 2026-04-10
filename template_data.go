package websession

import (
	"html/template"
)

// TemplateData is the data passed to the template
type TemplateData struct {
	ID       string
	RootId   string
	Title    string
	Username string
	LinkName string
	Models   []template.HTML
	FuncMap  template.FuncMap
}

func CreateTemplateData(id string, rid string, session *Session) TemplateData {
	return TemplateData{
		ID:       id,
		RootId:   rid,
		Username: session.UserName,
	}
}

func (d TemplateData) MakeTemplateFunc() template.FuncMap {
	if d.FuncMap != nil {
		return d.FuncMap
	}
	d.FuncMap = template.FuncMap{
		"gettopic": func() string {
			return "hello" //TODO: remove
		},
	}
	return d.FuncMap
}
