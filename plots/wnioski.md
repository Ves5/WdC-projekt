# Wnioski

## all_maxdiff_log.png/all_maxkeys_log.png

* RSA szybko przestaje nadawać się do szyfrowania i deszyfrowania dłuższych ciągów znaków.
* 3DES jest wolniejszy niż AES oraz Salsa20, a także szybciej traci efektywność czasową.
* AES oraz Salsa20 mają podobną efektywność czasową dla najdłużej pracującego przypadku, gdzie Salsa20 działa niewiele wolniej niż AES.
* Kryptografia asymetryczna szybko przestaje być opłacalna czasowo w porównaniu z kryptografią symetryczną.

## all_maxdiff_loglog.png/all_maxkeys_loglog.png

* Szyfrowanie i deszyfrowanie RSA mają około cały rząd różnicy w czasie dla tego samego rozmiaru
* W porównaniu z AES, RSA jest wolniejszy o mniej więcej 4-5 rzędów.
* 3DES w porównaniu do AES i Salsa20 także różni się o około 1 rząd.

## keys-3DES/AES/Salsa20

* Prędkość szyfrowania nie jest zależna od długości klucza, niezależnie od długości łańcucha znaków, czas pracy dla różnych długości kluczy był taki sam.

## keys-RSA

* W przeciwieństwie do algorytmów symetrycznych, prędkość enkrypcji i dekrypcji w RSA jest zależna od długości klucza.
* Im dłuższy klucz tym dłużej trwa algorytm.

## AES - modes

* ECB jest najszybszym trybem, a CBC najwolniejszym, CFB, OFB, CTR mają względnie zbliżone do siebie czasy enkrypcji i są niewiele wolniejsze od ECB.
* CBC jest mniej więcej 10 razy wolniejsze niż inne tryby.

## 3DES - modes

* ECB jest najszybszym trybem, CFB najwolniejszym, CBC, OFB i CTR zbliżone do siebie czasy.
* ECB jest 20-krotnie szybszy niż CFB, a pozostałe tryby znajdują się mniej więcej po środku, 10-krotnie wolniejsze niż ECB.

## block-stream

* Salsa20 ma podobny czas do AES, natomiast 3DES jest wolniejszy od obu.
