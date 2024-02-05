
rule Trojan_BAT_ClipBanker_ABS_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b 4d 12 00 28 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0c 08 07 6f 90 01 01 00 00 0a 28 90 00 } //0a 00 
		$a_03_1 = {00 00 0a 19 5d 59 0a 02 1f 41 06 73 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 28 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}