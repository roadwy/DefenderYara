
rule Trojan_BAT_Azorult_GN_MTB{
	meta:
		description = "Trojan:BAT/Azorult.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 0b 12 01 28 90 01 03 0a 0a 02 7b 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 91 06 02 7b 90 01 03 04 06 8e 69 5d 91 61 d2 9c 02 25 7b 90 01 03 04 17 58 7d 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}