
rule Trojan_BAT_ClipBanker_K_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 25 26 2c 90 01 01 7e 90 01 03 04 28 90 01 03 06 72 90 01 03 70 28 90 01 03 06 25 26 2c 90 0a 4d 00 7e 90 01 03 0a 28 90 01 03 06 28 90 01 03 06 25 72 90 01 03 70 28 90 01 03 06 2c 90 01 01 7e 90 01 03 04 28 90 01 03 06 25 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}