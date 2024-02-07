
rule Trojan_BAT_AveMaria_NAH_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 99 02 00 06 8c 90 01 03 01 73 90 01 03 0a a2 25 1f 0d 20 90 01 03 b2 28 90 01 03 06 04 6f 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {57 69 6e 66 6f 72 6d 73 5f 58 4d 4c 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  Winforms_XML.Properties
	condition:
		any of ($a_*)
 
}