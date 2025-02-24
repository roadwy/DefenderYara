
rule Trojan_BAT_RedlineStealer_SZA_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.SZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 11 15 1f 1f 5f 8f 89 00 00 01 25 4a 11 12 11 15 1e 5a 1f 1f 5f 63 61 54 11 15 17 58 13 15 11 15 1a fe 04 13 16 11 16 2d d6 } //1
		$a_81_1 = {41 63 63 6f 75 6e 74 5f 50 61 6e 65 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Account_Panel.Properties.Resources
		$a_81_2 = {24 33 65 62 32 30 32 35 33 2d 39 64 63 37 2d 34 31 31 39 2d 39 61 31 36 2d 35 63 62 37 36 33 65 38 65 33 65 38 } //1 $3eb20253-9dc7-4119-9a16-5cb763e8e3e8
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_RedlineStealer_SZA_MTB_2{
	meta:
		description = "Trojan:BAT/RedlineStealer.SZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 39 39 36 61 33 36 65 34 2d 36 34 63 38 2d 34 63 34 38 2d 62 63 33 33 2d 39 35 64 37 64 63 62 63 64 30 39 65 } //1 $996a36e4-64c8-4c48-bc33-95d7dcbcd09e
		$a_81_1 = {4a 59 4d 5f 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 JYM_Project.Properties.Resources.resources
		$a_00_2 = {00 11 04 11 14 8f 60 00 00 01 25 47 11 0e 11 14 1e 5a 1f 1f 5f 63 d2 61 d2 52 00 11 14 17 58 13 14 11 14 1a fe 04 13 15 11 15 2d d4 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}