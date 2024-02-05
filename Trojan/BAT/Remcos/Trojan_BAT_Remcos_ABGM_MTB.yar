
rule Trojan_BAT_Remcos_ABGM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 09 07 09 1e d8 1e 6f 90 01 03 0a 18 28 90 01 03 0a 9c 09 17 d6 0d 09 11 04 31 e4 90 00 } //02 00 
		$a_03_1 = {13 07 d0 34 90 01 02 01 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 17 8d 90 01 03 01 13 0c 11 0c 16 11 07 a2 11 0c 6f 90 01 03 0a 74 90 01 03 1b 13 06 90 00 } //01 00 
		$a_01_2 = {62 00 36 00 32 00 63 00 33 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}