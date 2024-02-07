
rule Backdoor_Win32_Oztratz_A{
	meta:
		description = "Backdoor:Win32/Oztratz.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 7a 6f 6e 65 20 52 41 54 2e 58 45 33 } //01 00  Ozone RAT.XE3
		$a_03_1 = {c7 45 fc ab 2a 03 00 43 81 e3 ff 00 00 00 8d 76 01 8a 94 1d 90 01 02 ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 00 89 4d f8 90 00 } //01 00 
		$a_03_2 = {56 57 68 ab 2a 03 00 e8 90 01 04 8b d8 83 ec 08 8b d3 e8 90 00 } //01 00 
		$a_03_3 = {8b 1e 81 fb 41 50 33 32 75 90 01 01 8b 5e 04 83 fb 18 90 00 } //00 00 
		$a_00_4 = {7e 15 00 } //00 60 
	condition:
		any of ($a_*)
 
}