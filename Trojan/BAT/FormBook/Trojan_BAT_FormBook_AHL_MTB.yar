
rule Trojan_BAT_FormBook_AHL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 d6 13 07 11 07 07 8e 69 fe 04 13 08 11 08 90 00 } //01 00 
		$a_01_1 = {54 00 61 00 62 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 45 00 78 00 74 00 72 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}