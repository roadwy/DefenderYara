
rule Trojan_Win64_LummaC_CCIS_MTB{
	meta:
		description = "Trojan:Win64/LummaC.CCIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 21 da 45 09 f9 44 09 d6 41 31 f1 44 88 4c 24 0b 44 8a 44 24 0b 48 8b 4c 24 10 48 63 54 24 0c 44 88 04 11 44 8b 54 24 0c } //1
		$a_01_1 = {44 21 de 09 f3 88 5c 24 2b 44 8a 44 24 2b 48 8b 4c 24 30 48 63 54 24 2c 44 88 04 11 44 8b 4c 24 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}