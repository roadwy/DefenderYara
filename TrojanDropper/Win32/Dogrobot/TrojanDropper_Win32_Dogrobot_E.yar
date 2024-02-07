
rule TrojanDropper_Win32_Dogrobot_E{
	meta:
		description = "TrojanDropper:Win32/Dogrobot.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 74 25 73 25 64 74 2e 65 78 65 } //01 00  ext%s%dt.exe
		$a_01_1 = {74 65 25 73 25 64 74 2e 64 6c 6c } //01 00  te%s%dt.dll
		$a_01_2 = {40 64 65 6c 20 33 35 39 36 37 39 39 61 31 35 34 33 62 63 39 66 2e 61 71 71 } //01 00  @del 3596799a1543bc9f.aqq
		$a_01_3 = {61 66 63 39 66 65 32 66 34 31 38 62 30 30 61 30 2e 62 61 74 } //01 00  afc9fe2f418b00a0.bat
		$a_01_4 = {5c 5c 2e 5c 70 63 69 64 75 6d 70 } //01 00  \\.\pcidump
		$a_01_5 = {0a c0 74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a } //01 00 
		$a_03_6 = {ff ff 63 c6 85 90 01 02 ff ff 6d c6 85 90 01 02 ff ff 64 c6 85 90 01 02 ff ff 20 c6 85 90 01 02 ff ff 2f c6 85 90 01 02 ff ff 63 c6 85 90 01 02 ff ff 20 c6 85 90 01 02 ff ff 73 c6 85 90 01 02 ff ff 63 c6 85 90 01 02 ff ff 20 90 00 } //02 00 
		$a_03_7 = {ff ff 73 c6 85 90 01 02 ff ff 63 c6 85 90 01 02 ff ff 76 c6 85 90 01 02 ff ff 68 c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 73 c6 85 90 01 02 ff ff 74 90 00 } //02 00 
		$a_01_8 = {8b 45 ec 03 45 d8 0f b6 00 83 c0 05 88 45 fc 6a 00 8d 45 e0 50 6a 01 8d 45 fc 50 ff 75 f4 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}