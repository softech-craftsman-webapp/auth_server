package view

type FileView struct {
	Name string `json:"name"`
	Url  string `json:"url"`
	Type string `json:"type"`
	Size int    `json:"size"`
}
