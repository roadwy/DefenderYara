
rule Worm_Win32_Gamarue_PLB_{
	meta:
		description = "Worm:Win32/Gamarue.PLB!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 74 00 6d 00 70 00 25 00 5c 00 74 00 76 00 2e 00 64 00 6c 00 6c 00 } //01 00  %tmp%\tv.dll
		$a_01_1 = {2c 22 74 76 69 64 22 3a 25 6c 75 2c 22 74 76 70 77 22 3a 25 6c 75 } //01 00  ,"tvid":%lu,"tvpw":%lu
		$a_03_2 = {68 83 4e 00 00 57 ff 15 90 01 04 8b f0 85 f6 74 40 68 00 01 00 00 8d 85 00 ff ff ff 50 68 82 4e 00 00 57 ff 15 90 01 04 85 c0 74 24 8d 85 00 ff ff ff 50 e8 90 01 04 8d 85 00 ff ff ff 50 ff 15 90 01 04 a3 90 01 04 89 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}