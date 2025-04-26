
rule Trojan_BAT_NjRat_NEO_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 06 72 f0 00 00 70 72 b5 01 00 70 6f 10 00 00 0a 00 72 b5 01 00 70 28 11 00 00 0a 26 00 de 0b } //1
		$a_01_1 = {39 00 64 00 62 00 62 00 39 00 33 00 64 00 31 00 34 00 65 00 37 00 64 00 38 00 38 00 30 00 66 00 2e 00 65 00 78 00 65 00 } //1 9dbb93d14e7d880f.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}