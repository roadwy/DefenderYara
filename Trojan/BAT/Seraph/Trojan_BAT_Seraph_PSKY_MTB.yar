
rule Trojan_BAT_Seraph_PSKY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.PSKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 4f 00 00 70 28 27 00 00 06 13 01 20 00 00 00 00 7e 90 01 03 04 7b 90 01 03 04 39 0f 00 00 00 26 20 90 01 03 00 38 04 00 00 00 fe 0c 02 00 90 01 09 38 00 00 00 00 28 90 01 03 06 11 01 6f 90 01 03 0a 72 8d 00 00 70 7e 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 06 13 03 38 00 00 00 00 dd 93 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}