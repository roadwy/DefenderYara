
rule Trojan_BAT_Remcos_ABXN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 0a 38 26 00 00 00 00 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0a dd 90 01 01 00 00 00 26 dd 00 00 00 00 06 2c d7 90 00 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}