
rule Trojan_BAT_Nanocore_ABSY_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? 00 00 06 15 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c e6 } //2
		$a_01_1 = {32 00 30 00 38 00 2e 00 36 00 37 00 2e 00 31 00 30 00 37 00 2e 00 31 00 34 00 36 } //2
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}