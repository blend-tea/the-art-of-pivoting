#
# Copy Noto Sans TTF font to your local directory - ~/.local/share/fonts/ 
# luaotfload-tool -u
#
cd ../book
pandoc README.md --columns=10  --from markdown+emoji --pdf-engine=lualatex -V colorlinks=true -V linkcolor=blue  -V urlcolor=red  -V toccolor=gray --number-sections -V toc-own-page=true -V footnotes-pretty=true -V table-use-row-color=true --template eisvogel  -o ../output/the-art-of-pivoting.pdf  -F mermaid-filter --toc --lof

pandoc README.md --columns=10  --from markdown+emoji -o ../output/the-art-of-pivoting.epub --toc --lof
