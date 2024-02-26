
rule Trojan_BAT_Injuke_AAWM_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 34 00 11 04 72 f5 00 00 70 12 08 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 11 05 1f 5a 20 97 00 00 00 6f 90 01 01 00 00 0a 73 90 01 01 00 00 06 6f 90 01 01 00 00 0a 00 00 11 08 17 58 13 08 11 08 1f 0a fe 04 13 09 11 09 2d c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}