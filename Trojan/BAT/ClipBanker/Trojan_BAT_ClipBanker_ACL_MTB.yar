
rule Trojan_BAT_ClipBanker_ACL_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1d 13 07 06 72 03 01 00 70 15 16 28 90 01 03 0a 0b 1e 13 07 19 09 07 19 9a 28 90 01 03 0a 1f 20 19 15 15 28 90 01 03 0a 00 1f 09 13 07 19 07 17 9a 15 6a 16 28 90 01 03 0a 00 1f 0a 13 07 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}