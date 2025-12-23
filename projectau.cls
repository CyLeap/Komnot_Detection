\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{projectau}[2024/01/01 v1.0 Project AU class]

% Load base class
\LoadClass[12pt,a4paper]{article}

% Packages
\RequirePackage[utf8]{inputenc}
\RequirePackage[T1]{fontenc}
\RequirePackage{lmodern}
\RequirePackage[english]{babel}
\RequirePackage{amsmath,amssymb,amsthm}
\RequirePackage{graphicx}
\RequirePackage{float}
\RequirePackage{booktabs}
\RequirePackage{siunitx}
\RequirePackage{chemmacros}
\RequirePackage{natbib}
\RequirePackage{fancyhdr}
\RequirePackage{geometry}
\RequirePackage{hyperref}
\RequirePackage{showkeys}

% Geometry
\geometry{margin=2.5cm}

% Metadata commands
\newcommand{\formation}{}
\newcommand{\promotion}{}
\newcommand{\project}{}
\newcommand{\projectname}{}
\newcommand{\headerlogo}{}

% Header setup
\fancypagestyle{fancy}{
    \fancyhf{}
    \fancyhead[L]{\projectname}
    \fancyhead[R]{\thepage}
    \renewcommand{\headrulewidth}{0.4pt}
}

% Title page
\renewcommand{\maketitle}{
    \begin{titlepage}
        \centering
        \vspace{2cm}
        {\Huge \projectname \par}
        \vspace{1cm}
        {\Large \formation \par}
        \vspace{0.5cm}
        {\large \promotion \par}
        \vspace{2cm}
        {\LARGE \thetitle \par}
        \vspace{1cm}
        {\large \theauthor \par}
        \vspace{0.5cm}
        {\large \theaffiliation \par}
        \vspace{2cm}
        {\large \thedate \par}
    \end{titlepage}
    \newpage
}

% Abstract
\renewenvironment{abstract}{
    \section*{Abstract}
}{
}

% Keywords
\newcommand{\keywords}[1]{
    \section*{Keywords}
    #1
}

\endinput
