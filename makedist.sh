#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

pip_hash=$(pip hash dist/pygost-"$release".tar.gz | sed -n '$p')
cp dist/pygost-"$release".tar.gz $tmp
cd $tmp
gunzip pygost-"$release".tar.gz
xz -9 pygost-"$release".tar
gpg --detach-sign --sign --local-user pygost@cypherpunks.ru pygost-"$release".tar.xz

tarball=pygost-"$release".tar.xz
size=$(( $(stat -f %z $tarball) / 1024 ))
hash=$(gpg --print-md SHA256 < $tarball)
hashsb=$($HOME/work/gogost/streebog256 < $tarball)
release_date=$(date "+%Y-%m-%d")

cat <<EOF
An entry for documentation:
@item @ref{Release $release, $release} @tab $release_date @tab $size KiB
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

PyGOST'es home page is: http://pygost.cypherpunks.ru/

Source code and its signature for that version can be found here:

    http://pygost.cypherpunks.ru/pygost-${release}.tar.xz ($size KiB)
    http://pygost.cypherpunks.ru/pygost-${release}.tar.xz.sig

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

Домашняя страница PyGOST: http://pygost.cypherpunks.ru/

Исходный код и его подпись для этой версии могут быть найдены здесь:

    http://pygost.cypherpunks.ru/pygost-${release}.tar.xz ($size KiB)
    http://pygost.cypherpunks.ru/pygost-${release}.tar.xz.sig

Streebog-256 хэш: $hashsb
SHA256 хэш: $hash
GPG ключ: F55A 7619 3A0C 323A A031  0E6B E6FD 1269 CD0C 009E
          PyGOST releases <pygost at cypherpunks dot ru>

Пожалуйста, все вопросы касающиеся использования PyGOST, отчёты об
ошибках и патчи отправляйте в gost почтовую рассылку:
https://lists.cypherpunks.ru/mailman/listinfo/gost
EOF

mv $tmp/$tarball $tmp/"$tarball".sig $cur/pygost.html/
