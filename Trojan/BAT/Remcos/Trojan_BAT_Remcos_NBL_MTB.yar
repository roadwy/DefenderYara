
rule Trojan_BAT_Remcos_NBL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 6f 98 03 90 01 02 08 07 5d 91 0d 0e 04 08 0e 05 58 03 08 04 58 91 02 6f 96 03 90 01 02 09 06 5d 91 61 d2 9c 08 17 58 0c 08 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}