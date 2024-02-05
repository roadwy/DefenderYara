
rule Trojan_BAT_Remcos_EAC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 91 13 06 02 74 90 01 01 00 00 1b 11 04 09 11 04 11 05 5d 91 11 06 61 b4 9c 11 04 17 d6 13 04 00 11 04 20 90 02 04 fe 01 16 fe 01 13 0a 11 0a 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}