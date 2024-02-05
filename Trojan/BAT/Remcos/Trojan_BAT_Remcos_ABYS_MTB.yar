
rule Trojan_BAT_Remcos_ABYS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {02 72 0d 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0a dd 90 01 01 00 00 00 26 dd 00 00 00 00 06 2c d1 06 2a 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00 
	condition:
		any of ($a_*)
 
}