
rule Trojan_Win32_Klabnel_A{
	meta:
		description = "Trojan:Win32/Klabnel.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 78 64 42 34 35 31 31 31 63 63 39 63 33 30 34 38 45 65 46 41 35 32 35 66 44 62 39 37 37 39 61 61 30 36 35 32 34 42 37 41 31 2e 31 33 37 36 } //1 0xdB45111cc9c3048EeFA525fDb9779aa06524B7A1.1376
		$a_01_1 = {76 69 72 74 75 61 6c 33 39 34 39 39 2e 6e 65 74 3a 39 30 30 33 } //1 virtual39499.net:9003
		$a_01_2 = {6d 69 6e 65 31 2e 63 6f 69 6e 6d 69 6e 65 2e 70 6c 3a 31 39 39 39 } //1 mine1.coinmine.pl:1999
		$a_01_3 = {63 67 6d 69 6e 65 72 20 33 2e 37 2e 32 } //1 cgminer 3.7.2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}