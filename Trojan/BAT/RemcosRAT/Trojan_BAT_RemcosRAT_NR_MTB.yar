
rule Trojan_BAT_RemcosRAT_NR_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {58 13 03 20 0e 00 00 00 fe 90 01 02 00 38 90 01 03 ff 16 6a 13 00 20 90 01 03 00 fe 90 01 02 00 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {42 6e 6e 69 79 64 74 64 } //00 00  Bnniydtd
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_RemcosRAT_NR_MTB_2{
	meta:
		description = "Trojan:BAT/RemcosRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {17 2d 06 d0 11 00 00 06 26 72 90 01 01 00 00 70 0a 06 28 90 01 01 00 00 0a 25 26 0b 28 90 01 01 00 00 0a 25 26 07 16 07 8e 69 6f 90 01 01 00 00 0a 0a 28 90 01 01 00 00 0a 25 26 06 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {42 48 48 48 47 36 36 } //00 00  BHHHG66
	condition:
		any of ($a_*)
 
}