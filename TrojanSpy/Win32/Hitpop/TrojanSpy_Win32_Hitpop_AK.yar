
rule TrojanSpy_Win32_Hitpop_AK{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {26 76 65 72 3d } //01 00  &ver=
		$a_00_1 = {26 74 67 69 64 3d } //01 00  &tgid=
		$a_00_2 = {26 61 64 64 72 65 73 73 3d } //01 00  &address=
		$a_00_3 = {3f 61 64 64 72 65 73 73 3d } //01 00  ?address=
		$a_00_4 = {26 75 72 6c 3d } //01 00  &url=
		$a_00_5 = {6d 79 64 6f 77 6e } //01 00  mydown
		$a_00_6 = {6e 6f 6e 67 6d 69 6e 33 32 2e 69 6e 69 } //01 00  nongmin32.ini
		$a_00_7 = {6e 6f 6e 67 6d 69 6e 31 36 2e 69 6e 69 } //01 00  nongmin16.ini
		$a_00_8 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_00_9 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_03_10 = {6a 00 6a 00 8b 45 e4 e8 90 01 02 ff ff 50 8b 45 f4 e8 90 01 02 ff ff 50 6a 00 e8 90 01 02 ff ff 8b 45 e4 50 e8 90 01 02 ff ff 84 c0 75 0b 8b 55 e4 8b 45 f4 e8 90 01 02 ff ff 8b 45 f4 e8 90 01 02 ff ff 8b 45 e4 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}