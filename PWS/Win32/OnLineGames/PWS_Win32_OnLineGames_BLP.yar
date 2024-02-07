
rule PWS_Win32_OnLineGames_BLP{
	meta:
		description = "PWS:Win32/OnLineGames.BLP,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 44 46 44 } //01 00  C:\DFD
		$a_00_1 = {3a 4c 6f 6f 70 } //01 00  :Loop
		$a_00_2 = {64 65 6c 20 25 30 } //01 00  del %0
		$a_00_3 = {53 65 6e 64 47 61 6d 65 44 61 74 61 } //01 00  SendGameData
		$a_00_4 = {55 72 6c 25 64 } //01 00  Url%d
		$a_00_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4e 65 74 4d 65 65 74 69 6e 67 5c 2a 2e 63 66 67 } //01 00  C:\Program Files\NetMeeting\*.cfg
		$a_00_6 = {6d 79 68 70 72 69 2e 64 6c 6c } //01 00  myhpri.dll
		$a_00_7 = {72 73 6d 79 61 70 6d 2e 64 6c 6c } //01 00  rsmyapm.dll
		$a_00_8 = {7b 31 45 33 32 46 41 35 38 2d 33 34 35 33 2d 46 41 32 44 2d 42 43 34 39 2d 46 33 34 30 33 34 38 41 43 43 45 31 7d } //01 00  {1E32FA58-3453-FA2D-BC49-F340348ACCE1}
		$a_00_9 = {70 6c 61 79 2e 65 78 65 } //01 00  play.exe
		$a_00_10 = {73 6f 75 6c 2e 65 78 65 } //01 00  soul.exe
		$a_00_11 = {45 6e 48 6f 6f 6b 57 69 6e 64 6f 77 } //01 00  EnHookWindow
		$a_00_12 = {53 6b 69 70 46 69 72 65 57 61 6c 6c } //01 00  SkipFireWall
		$a_01_13 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_01_14 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 41 } //00 00  MapVirtualKeyA
	condition:
		any of ($a_*)
 
}