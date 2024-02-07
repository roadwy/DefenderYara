
rule Trojan_BAT_Remcos_EAV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {06 72 01 00 00 70 6f 90 01 01 00 00 0a 11 02 28 90 01 01 00 00 0a 72 01 00 00 70 6f 90 01 01 00 00 0a 8e 69 5d 91 7e 90 01 01 00 00 04 11 02 91 61 d2 6f 90 01 01 00 00 0a 38 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}