#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

cp dist/pygost-"$release".tar.gz $tmp
cd $tmp
gunzip pygost-"$release".tar.gz
xz -9 pygost-"$release".tar
gpg --detach-sign --sign --local-user E6FD1269CD0C009E pygost-"$release".tar.xz

tarball=pygost-"$release".tar.xz
size=$(( $(wc -c < $tarball) / 1024 ))
hash=$(gpg --print-md SHA256 < $tarball)
hashsb=$($HOME/work/gogost/gogost-streebog < $tarball)

cat <<EOF
An entry for documentation:
@item $release @tab $size KiB
@tab @url{pygost-${release}.tar.xz, link} @url{pygost-${release}.tar.xz.sig, sign}
@tab @code{$hash}
@tab @code{$hashsb}
EOF

cat <<EOF
Subject: [EN] PyGOST $release release announcement

I am pleased to announce PyGOST $release release availability!

PyGOST is free software pure Python GOST cryptographic functions library.
GOST is GOvernment STandard of Russian Federation (and Soviet Union).

------------------------ >8 ------------------------

The main improvements for that release are:


------------------------ >8 ------------------------

PyGOST'es home page is: http://www.cypherpunks.ru/pygost/

Source code and its signature for that version can be found here:

    http://www.cypherpunks.ru/pygost/pygost-${release}.tar.xz ($size KiB)
    http://www.cypherpunks.ru/pygost/pygost-${release}.tar.xz.sig

Streebog-256 hash: $hashsb
SHA256 hash: $hash
GPG key: F55A 7619 3A0C 323A A031  0E6B E6FD 1269 CD0C 009E
         PyGOST releases <pygost at cypherpunks dot ru>

Please send questions regarding the use of PyGOST, bug reports and patches
to mailing list: https://lists.cypherpunks.ru/mailman/listinfo/gost
EOF

cat <<EOF
Subject: [RU] Состоялся релиз PyGOST $release

Я рад сообщить о выходе релиза PyGOST $release!

PyGOST это свободное программное обеспечение реализующее
криптографические функции ГОСТ на чистом Python. ГОСТ -- ГОсударственный
СТандарт Российской Федерации (а также Советского Союза).

------------------------ >8 ------------------------

Основные усовершенствования в этом релизе:


------------------------ >8 ------------------------

Домашняя страница PyGOST: http://www.cypherpunks.ru/pygost/

Исходный код и его подпись для этой версии могут быть найдены здесь:

    http://www.cypherpunks.ru/pygost/pygost-${release}.tar.xz ($size KiB)
    http://www.cypherpunks.ru/pygost/pygost-${release}.tar.xz.sig

Streebog-256 хэш: $hashsb
SHA256 хэш: $hash
GPG ключ: F55A 7619 3A0C 323A A031  0E6B E6FD 1269 CD0C 009E
          PyGOST releases <pygost at cypherpunks dot ru>

Пожалуйста, все вопросы касающиеся использования PyGOST, отчёты об
ошибках и патчи отправляйте в gost почтовую рассылку:
https://lists.cypherpunks.ru/mailman/listinfo/gost
EOF

mv $tmp/$tarball $tmp/"$tarball".sig $cur/pygost.html/
