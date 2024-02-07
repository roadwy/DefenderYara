
rule Trojan_BAT_Shelpak_MBEZ_MTB{
	meta:
		description = "Trojan:BAT/Shelpak.MBEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 50 c3 00 00 73 90 01 01 01 00 0a 0c 07 08 07 6f 90 01 01 01 00 0a 1e 5b 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 00 07 08 07 6f 90 01 01 01 00 0a 1e 5b 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 00 07 1a 90 00 } //01 00 
		$a_03_1 = {20 50 c3 00 00 73 90 01 01 01 00 0a 13 04 09 11 04 09 6f 90 01 01 01 00 0a 1e 5b 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 00 09 11 04 09 6f 90 01 01 01 00 0a 1e 5b 90 00 } //0a 00 
		$a_01_2 = {39 38 37 34 2d 65 30 64 33 38 35 66 66 33 34 33 31 } //00 00  9874-e0d385ff3431
	condition:
		any of ($a_*)
 
}