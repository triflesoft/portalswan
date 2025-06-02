//go:build ignore
// +build ignore

package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/message/pipeline"
)

func noErr(err error) {
	if err != nil {
		panic(err)
	}
}

type nextFiles []string

func (i *nextFiles) String() string {
	return "my string representation"
}

func (i *nextFiles) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Inspired by gotext cmd, but without the slow as f*** scanning part. Just extract
// translations from templates file with a naive regex. Yup.
// Usage go:generate go run main.go -srclang=en-GB -out=catalog.go -lang=en-GB,de-DE,fr-CH update templates-dir
// Ex go:generate go run ../cmd/gen-translations/main.go -srclang=en -out=catalog.go -lang=en,fr update ../../templates
// Ex go:generate go run update ../../templates --next=client/core/translation-en.json
func main() {
	args := new(struct {
		SrcLang string
		Out     string
		Lang    string
		Dir     string
		Cmd     string
		Nexts   nextFiles
		OutNext string
	})

	// flag.
	flag.StringVar(&args.SrcLang, "srclang", "", "")
	flag.StringVar(&args.Out, "out", "", "")
	flag.StringVar(&args.OutNext, "out-next", "", "where out files lands")
	flag.StringVar(&args.Lang, "lang", "", "")
	flag.Var(&args.Nexts, "next", "Spitted out files by babel compilation")
	flag.Parse()

	rem := flag.Args()

	if len(rem) != 2 {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	args.Cmd = rem[0]
	args.Dir = rem[1]

	if args.Cmd != "update" {
		panic("unsupported command")
	}

	// `some template {{ l10n "foo" }}` => some template bar
	l10nPattern := regexp.MustCompile(`\{\{\s*l10n\s+\"((?:[^"\\]|\\.)*)\"\s*(?:(\$[\.A-Za-z0-9]+)\s*)?(?:(\$[\.A-Za-z0-9]+)\s*)?(?:(\$[\.A-Za-z0-9]+)\s*)?(?:(\$[\.A-Za-z0-9]+)\s*)?\}\}`)
	messages := []pipeline.Message{}

	err := filepath.Walk(args.Dir, func(path string, info fs.FileInfo, err error) error {
		noErr(err)

		if filepath.Ext(info.Name()) == ".html" && !info.IsDir() {
			b, err := os.ReadFile(path)

			noErr(err)

			l10nMatches := l10nPattern.FindAllStringSubmatch(string(b), -1)

			for _, l10nMatch := range l10nMatches {
				message := pipeline.Message{
					ID:  pipeline.IDList{l10nMatch[1]},
					Key: l10nMatch[1],
					Message: pipeline.Text{
						Msg: l10nMatch[1],
					},
					Placeholders: []pipeline.Placeholder{},
				}

				for i := 2; i < len(l10nMatch); i++ {
					if l10nMatch[i] != "" {
						message.Placeholders = append(message.Placeholders, pipeline.Placeholder{
							ID:             fmt.Sprintf("arg%d", i-1),
							String:         fmt.Sprintf("%%[%d]s", i-1),
							Type:           "string",
							UnderlyingType: "string",
							ArgNum:         i - 1,
							Expr:           fmt.Sprintf("arg%d", i-1),
							Comment:        "From HTML template",
						})
					}
				}

				messages = append(messages, message)
			}
		}

		return nil
	})

	noErr(err)

	supported := []language.Tag{}

	for _, l := range strings.Split(args.Lang, ",") {
		supported = append(supported, language.Make(l))
	}

	state := pipeline.State{
		Extracted: pipeline.Messages{
			Language: language.Make(args.SrcLang),
			Messages: messages,
		},
		Config: pipeline.Config{
			Supported:      supported,
			SourceLanguage: language.Make(args.SrcLang),
			GenFile:        args.Out,
		},
		Translations: nil,
	}

	noErr(state.Import())
	noErr(state.Merge())
	noErr(state.Export())
	noErr(state.Generate())

	fmt.Println("ok")
}
