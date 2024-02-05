
rule Trojan_BAT_Bladabindi_NQG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 41 00 00 70 0a 73 1e 00 00 0a 0b 16 0c 2b 37 00 06 28 90 01 03 0a 0d 03 08 94 06 6f 90 01 03 0a 20 80 00 00 00 61 5b 13 04 11 04 09 20 00 01 00 00 5a 16 60 59 d2 13 05 07 11 05 6f 90 01 03 0a 00 00 08 17 58 0c 08 03 8e 69 fe 04 13 06 11 06 2d bd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}