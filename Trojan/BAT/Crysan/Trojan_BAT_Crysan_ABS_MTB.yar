
rule Trojan_BAT_Crysan_ABS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 0f 00 08 20 00 04 00 00 58 28 01 00 00 2b 00 07 02 08 20 00 04 00 00 6f 90 01 01 00 00 0a 0d 08 09 58 0c 00 09 20 00 04 00 00 fe 04 16 fe 01 13 04 11 04 2d cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}