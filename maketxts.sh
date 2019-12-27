#!/bin/sh -ex

texi=$(mktemp)

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS
@node News
@unnumbered News
`sed -n '3,$p' < news.texi`
@bye
EOF
makeinfo --plaintext -o NEWS $texi

cat > download.texi <<EOF
You can obtain releases source code prepared tarballs on
@url{http://pygost.cypherpunks.ru/}.
EOF

perl -i -p -e 's/hash=sha256:\w+/hash=sha256:TARBALL-HASH/' install.texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle INSTALL
@include install.texi
@bye
EOF
makeinfo --plaintext -o INSTALL $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle FAQ
@include faq.texi
@bye
EOF
makeinfo --plaintext -o FAQ $texi

rm -f $texi

git checkout download.texi install.texi
