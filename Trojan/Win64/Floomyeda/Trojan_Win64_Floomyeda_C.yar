
rule Trojan_Win64_Floomyeda_C{
	meta:
		description = "Trojan:Win64/Floomyeda.C,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 00 30 00 31 00 35 00 2d 00 30 00 34 00 2d 00 31 00 38 00 54 00 } //10 2015-04-18T
		$a_01_1 = {54 24 54 69 42 7a 78 56 40 32 32 } //10 T$TiBzxV@22
		$a_01_2 = {54 24 54 69 43 77 78 56 40 31 32 54 72 32 32 32 35 33 } //10 T$TiCwxV@12Tr22253
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}