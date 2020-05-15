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

* Prędkość szyfrowania nie jest zależna od długości klucza, niezależnie od długości łańcucha znaków, czas pracy był taki sam.

## keys-RSA

* W przeciwieństwie do algorytmów symetrycznych, prędkość enkrypcji i dekrypcji w RSA jest zależna od długości klucza.
* Im dłuższy klucz tym dłużej trwa algorytm.
