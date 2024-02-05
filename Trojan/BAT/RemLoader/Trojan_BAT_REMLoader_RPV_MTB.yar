
rule Trojan_BAT_REMLoader_RPV_MTB{
	meta:
		description = "Trojan:BAT/REMLoader.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 } //01 00 
		$a_01_1 = {5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b8 } //00 00 
	condition:
		any of ($a_*)
 
}