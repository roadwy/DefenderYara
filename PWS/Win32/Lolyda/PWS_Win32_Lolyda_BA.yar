
rule PWS_Win32_Lolyda_BA{
	meta:
		description = "PWS:Win32/Lolyda.BA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 11 7c 0f 8a 14 01 80 f2 90 01 01 80 c2 90 01 01 88 14 01 48 79 f1 90 00 } //01 00 
		$a_00_1 = {25 00 6c 00 73 00 25 00 68 00 73 00 5f 00 2e 00 62 00 6d 00 70 00 00 00 } //01 00 
		$a_01_2 = {c6 00 e8 2b 4c 24 0c 83 e9 05 89 48 01 } //01 00 
		$a_01_3 = {25 68 73 3f 61 63 74 3d 26 64 31 30 3d 25 68 73 26 64 38 30 3d 25 64 00 } //00 00  栥㽳捡㵴搦〱┽獨搦〸┽d
	condition:
		any of ($a_*)
 
}