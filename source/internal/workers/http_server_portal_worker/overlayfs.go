package http_server_portal_worker

import (
	"embed"
	"io/fs"
)

//go:embed webroot
var webrootFS embed.FS

//go:embed template
var templateFS embed.FS

//go:embed attachment
var attachmentFS embed.FS

type overlayFS struct {
	filesystems []fs.FS
}

func NewOverlayFS(filesystems ...fs.FS) *overlayFS {
	return &overlayFS{
		filesystems: filesystems,
	}
}

func (ofs overlayFS) Open(name string) (fs.File, error) {
	for _, f := range ofs.filesystems {
		file, err := f.Open(name)

		if err == nil {
			return file, nil
		}
	}

	return nil, fs.ErrExist
}

func (ofs overlayFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entriesMap := make(map[string]fs.DirEntry)

	for _, f := range ofs.filesystems {
		if rdFS, ok := f.(fs.ReadDirFS); ok {
			entries, err := rdFS.ReadDir(name)

			if err != nil {
				continue
			}

			for _, entry := range entries {
				entriesMap[entry.Name()] = entry
			}
		}
	}

	var entries []fs.DirEntry

	for _, entry := range entriesMap {
		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return nil, fs.ErrNotExist
	}

	return entries, nil
}
