
rule Trojan_BAT_NjRAT_PSWG_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {1f 0a 31 50 73 08 00 00 0a 13 20 07 16 9a 7e 19 00 00 04 07 17 9a 7e 19 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 1f 11 20 02 11 1f 02 8e b7 11 1f da 6f 90 01 01 00 00 0a 11 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}