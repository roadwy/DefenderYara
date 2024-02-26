
rule Trojan_BAT_Gozi_NG_MTB{
	meta:
		description = "Trojan:BAT/Gozi.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {19 8d 6d 00 00 01 0a 06 16 02 a2 06 17 03 8c 90 01 02 00 01 a2 06 18 04 a2 28 90 01 02 00 06 28 90 01 02 00 06 72 90 01 02 00 70 06 28 90 01 02 00 06 2a 90 00 } //01 00 
		$a_01_1 = {58 6f 6c 61 64 6f 6e 69 76 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Xoladoniv.g.resources
	condition:
		any of ($a_*)
 
}