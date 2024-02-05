
rule Trojan_BAT_Artemis_AWB_MTB{
	meta:
		description = "Trojan:BAT/Artemis.AWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 08 9a 6f 90 01 03 0a 72 90 01 03 70 16 28 90 01 03 0a 2d 02 17 0a 08 17 d6 90 00 } //01 00 
		$a_01_1 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 5f 00 41 00 4c 00 54 00 44 00 4e 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}