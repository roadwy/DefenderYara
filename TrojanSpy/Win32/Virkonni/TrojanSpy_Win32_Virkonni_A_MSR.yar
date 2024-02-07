
rule TrojanSpy_Win32_Virkonni_A_MSR{
	meta:
		description = "TrojanSpy:Win32/Virkonni.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 65 6d 62 65 72 2d 64 61 75 6d 63 68 6b 2e 6e 65 74 61 69 2e 6e 65 74 2f 77 65 67 65 74 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 66 69 6c 65 3d 37 38 37 43 31 36 34 38 5f 64 72 6f 70 63 6f 6d } //02 00  http://member-daumchk.netai.net/weget/download.php?file=787C1648_dropcom
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 2f 77 65 67 65 74 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 66 69 6c 65 3d 25 73 5f 64 72 6f 70 63 6f 6d } //01 00  http://%s/weget/download.php?file=%s_dropcom
		$a_00_2 = {49 00 4e 00 54 00 45 00 52 00 4e 00 41 00 4c 00 5c 00 52 00 45 00 4d 00 4f 00 54 00 45 00 2e 00 45 00 58 00 45 00 } //01 00  INTERNAL\REMOTE.EXE
		$a_01_3 = {54 68 69 73 20 63 6f 6d 70 75 74 65 72 27 73 20 49 50 20 41 64 64 72 65 73 73 20 69 73 } //01 00  This computer's IP Address is
		$a_01_4 = {79 73 65 6c 66 2e 64 6c 6c } //01 00  yself.dll
		$a_00_5 = {50 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 72 00 65 00 70 00 61 00 69 00 72 00 65 00 64 00 } //01 00  Packages\microsoft\repaired
		$a_01_6 = {30 36 32 36 5c 76 69 72 75 73 2d 6c 6f 61 64 5c 5f 52 65 73 75 6c 74 36 34 5c 76 69 72 75 73 2d 64 6c 6c 2e 70 64 62 } //00 00  0626\virus-load\_Result64\virus-dll.pdb
	condition:
		any of ($a_*)
 
}