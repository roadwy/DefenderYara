
rule Trojan_BAT_Remcos_ARS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e 03 01 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 19 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARS_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 0b 06 8e 69 17 59 0c 38 16 00 00 00 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARS_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 7e 01 00 00 04 07 6f 90 01 03 0a 00 7e 01 00 00 04 18 6f 90 01 03 0a 00 02 05 03 04 16 28 90 01 03 06 0c 2b 00 08 2a 90 00 } //01 00 
		$a_01_1 = {73 61 6c 61 6d 61 6e 63 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARS_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 38 3f 00 00 00 28 90 01 03 06 75 01 00 00 1b 28 90 01 03 0a 0b d0 01 00 00 01 28 90 01 03 0a 72 01 00 00 70 28 90 01 03 0a 07 14 6f 90 01 03 0a 75 02 00 00 1b 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}