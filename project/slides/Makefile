.PHONY all: presentation.pdf

presentation.pdf: presentation.tex
	pdflatex presentation.tex
	pdflatex presentation.tex
	pdflatex presentation.tex

.PHONY clean:
	rm -f *.aux *.log *.nav *.out *.toc *.snm *.vrb *.pdfpc presentation.pdf
