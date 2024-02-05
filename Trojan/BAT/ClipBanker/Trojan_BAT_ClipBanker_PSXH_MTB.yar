
rule Trojan_BAT_ClipBanker_PSXH_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PSXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 07 28 1f 00 00 0a 0d 09 14 fe 03 13 04 11 04 39 b5 00 00 00 00 07 72 7f 00 00 70 6f 23 00 00 0a 13 05 11 05 2c 12 00 72 85 00 00 70 28 24 00 00 0a 00 00 38 90 } //00 00 
	condition:
		any of ($a_*)
 
}