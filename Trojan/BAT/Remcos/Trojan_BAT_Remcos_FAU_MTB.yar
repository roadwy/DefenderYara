
rule Trojan_BAT_Remcos_FAU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 13 00 38 00 00 00 00 28 90 01 01 00 00 0a 11 00 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 01 38 00 00 00 00 02 11 01 28 90 01 01 00 00 06 13 02 38 00 00 00 00 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}