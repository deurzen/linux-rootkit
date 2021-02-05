\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{i20lecture}[2016/09/01 I20Lecture]

\LoadClass[xcolor={usenames,dvipsnames}]{beamer}

\mode<presentation>{\usetheme[wide, dark]{tum}}
%% Available Options:
%% dark     Use dark theme (default: off)
%% en       English presentation (default: off)
%% minimal  Be minimalistic (default: off)
%% wide     Produce 16:9 slides (default: on)

\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{default}
\usepackage{amsmath}
\usepackage{wasysym}
\usepackage{calc}
%\usepackage{pdfpcnotes}
\usepackage{tikz}
\usetikzlibrary{positioning, calc, arrows, calendar, scopes, backgrounds, patterns,
  shapes, fit, matrix, petri, decorations.pathreplacing}
\usepackage{listings}
\usepackage{booktabs}
\usepackage{dcolumn}
\usepackage[defaultmono, scale = .8]{droidsansmono}
\usepackage{palatino}
\usepackage{url}
\usepackage{pifont}
\usepackage{subfigure}
\usepackage[absolute,overlay]{textpos}
\usefonttheme{serif}
\newcolumntype{d}[1]{D{.}{.}{#1}}
\usepackage{standalone}
\usepackage{eurosym}
\usepackage{extarrows}
\usepackage{todonotes}

\usepackage{fancyvrb}
\renewcommand*\ttdefault{fdm}

% https://en.wikibooks.org/wiki/LaTeX/Source_Code_Listings
\lstset{
  numbers=left,
  numberstyle=\tiny\color{gray},
  stepnumber=1,
  numbersep=5pt,
  showspaces=false,
  showstringspaces=false,
  showtabs=false,
  frame=single,
  rulecolor=\color{black},
  tabsize=2,
  captionpos=b,
  breaklines=true,
  breakatwhitespace=false,
  language=C,
  commentstyle=\itshape\color{Mahogany},
  stringstyle=\color{BrickRed},
  keywordstyle=\bfseries\color{OliveGreen},
  keywordstyle=[2]{\color{MidnightBlue}},
  keywordstyle=[3]{\color{RoyalPurple}},
  escapechar=ÃŸ,
  xleftmargin=8pt,
  xrightmargin=3pt,
  basicstyle=\scriptsize\fdmfamily,
  morekeywords={u32, __u32, __be32, __le32,
    u16, __u16, __be16, __le16,
    u8,  __u8,  __be8,  __le8,
    size_t, ssize_t, uint64_t}
}

%kirschju's masm lstlisting
\lstnewenvironment{asmcode}{\lstset{
  language=[x86masm]Assembler,
  % TODO: Add missing keywords here
  keywords={mov, call, ret, xor, rep, int, loop, push, syscall, pop,
      cdqe, cqo, cmpsq, cmpxchg16b, jrcxz, lodsq, movsxd, sub, add,
      vxorpd, popfq, pushfq, scasq, stosq, iretq, rdtscp, swapgs, leave},
    keywords=[2]{rax, eax, ax, ah, al,
      rdx, edx, dx, dh, dl,
      rcx, ecx, cx, ch, cl,
      rbx, ebx, bx, bh, bl,
      rsi, esi, si, sih, sil,
      rdi, edi, di, dih, dil,
      rsp, esp, sp, rbp, ebp, bp, rip, eip, ip,
      r8, r8d, r8w, r8b, r9, r9d, r9w, r9b,
      r10, r10d, r10w, r10b, r11, r11d, r11w, r11b,
      r12, r12d, r12w, r12b, r13, r13d, r13w, r13b,
      r14, r14d, r14w, r14b, r15, r15d, r15w, r15b},
    keywords=[3]{db, section},
  comment=[]{},
  morecomment=[s]{/*}{*/},
  commentstyle=\itshape\color{Mahogany},
  identifierstyle=\color{Black},
  stringstyle=\color{Orange},
}}{}

\lstnewenvironment{ccode}{\lstset{
  language=C,
  keywordstyle=\bfseries\color{LimeGreen},
  commentstyle=\itshape\color{Mahogany},
  %identifierstyle=\color{BrickRed},
  stringstyle=\color{Orange},
  morekeywords={u32, __u32, __be32, __le32,
    u16, __u16, __be16, __le16,
    u8,  __u8,  __be8,  __le8,
    size_t, ssize_t, uint64_t, uint32_t}
}}{}

%\newcommand{\currentchapter}{}
%\let\oldchapter\chapter
%\renewcommand{\chapter}[1]{
%	\oldchapter{#1}
%	\renewcommand{\currentchapter}{#1}
%}

\newcommand{\currentsection}{}
\let\oldsection\section
\renewcommand{\section}[1]{
	\oldsection{#1}
	\renewcommand{\currentsection}{#1}
	\renewcommand{\currentsubsection}{\ }
	\renewcommand{\currentsubsubsection}{\ }
}

\newcommand{\currentsubsection}{}
\let\oldsubsection\subsection
\renewcommand{\subsection}[1]{
	\oldsubsection{#1}
	\renewcommand{\currentsubsection}{#1}
	\renewcommand{\currentsubsubsection}{\ }
}

\newcommand{\currentsubsubsection}{}
\let\oldsubsubsection\subsubsection
\renewcommand{\subsubsection}[1]{
	\oldsubsubsection{#1}
	\renewcommand{\currentsubsubsection}{#1}
}

% META
% =========================================================
\title[None]{Rootkit Programming - Final Presentation}
\author[Max v. D., Tizian L.]{Max van Deurzen, Tizian Leonhardt}
\semester{Wintersemester 2020/21}
\institute{}
\date{10. February, 2021}
% =========================================================
