
rule Trojan_BAT_NjRAT_C_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 00 0a 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 } //02 00 
		$a_03_1 = {00 00 01 11 05 11 0a 74 90 01 01 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 90 01 01 00 00 1b 11 09 11 0c 58 1f 90 01 01 58 11 08 5d 93 61 d1 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}