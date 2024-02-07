
rule Trojan_BAT_Bladabindi_NW_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 2d 11 2b 1f 2d 0d 16 2d f6 2b 1b 2b 1c 2b 1d 2b 1e 2b 0a 2b 21 2b 22 } //01 00 
		$a_01_1 = {9d a2 3f 09 1f 00 00 00 98 00 33 00 16 00 00 01 00 00 00 c2 00 00 00 2d 00 00 00 48 01 00 00 f7 00 00 00 b9 00 00 00 5d 01 00 00 34 } //01 00 
		$a_01_2 = {32 38 30 64 61 35 34 65 32 33 34 34 } //00 00  280da54e2344
	condition:
		any of ($a_*)
 
}