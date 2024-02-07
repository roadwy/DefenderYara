
rule TrojanDropper_Win32_Hokobot_A_dha{
	meta:
		description = "TrojanDropper:Win32/Hokobot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 3c 18 5e 0f 85 90 01 04 80 7c 18 01 2a 0f 85 90 01 04 80 7c 18 02 21 0f 85 90 01 04 80 7c 18 03 23 0f 85 90 01 04 80 7c 18 04 5e 0f 85 90 01 04 80 7c 18 05 60 0f 85 90 01 04 80 7c 18 06 7c 90 00 } //01 00 
		$a_00_1 = {8b cd 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 83 7b 18 10 89 6b 14 } //01 00 
		$a_00_2 = {5e 2a 21 23 5e 60 7c 77 69 6e 73 65 63 2e 64 6c 6c 5e 2a 21 23 5e 60 7c 77 69 6e 69 6e 65 74 2e 65 78 65 } //01 00  ^*!#^`|winsec.dll^*!#^`|wininet.exe
		$a_00_3 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f } //00 00  TVqQAAMAAAAEAAAA//
		$a_00_4 = {5d 04 00 } //00 42 
	condition:
		any of ($a_*)
 
}