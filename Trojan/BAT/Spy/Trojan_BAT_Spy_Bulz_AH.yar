
rule Trojan_BAT_Spy_Bulz_AH{
	meta:
		description = "Trojan:BAT/Spy.Bulz.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {fa 25 33 00 16 90 01 02 01 90 01 03 1c 90 01 03 07 90 01 03 05 90 01 03 11 90 01 03 03 90 01 03 29 90 01 03 2a 90 01 03 0c 90 01 03 02 90 01 03 05 90 01 03 05 90 00 } //03 00 
		$a_80_1 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 } //GetEnvironmentVariable  03 00 
		$a_80_2 = {5c 63 6d 64 2e 62 61 74 } //\cmd.bat  03 00 
		$a_80_3 = {57 72 69 74 65 41 6c 6c 54 65 78 74 } //WriteAllText  00 00 
	condition:
		any of ($a_*)
 
}