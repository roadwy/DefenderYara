
rule VirTool_WinNT_Rootkitdrv_OK_bit{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.OK!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 77 00 6f 00 6e 00 69 00 75 00 6c 00 6f 00 63 00 6b 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 75 00 67 00 75 00 61 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 6e 00 61 00 6d 00 65 00 3d 00 } //01 00  http://www.woniulock.com/tuguan.php?name=
		$a_01_1 = {5b 49 6e 6a 65 63 74 42 79 48 6f 6f 6b 33 32 5d } //01 00  [InjectByHook32]
		$a_01_2 = {5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 73 00 61 00 66 00 65 00 6d 00 6f 00 6e 00 2e 00 64 00 61 00 74 00 } //01 00  \??\C:\Program Files\Common Files\System\safemon.dat
		$a_01_3 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 2a 63 68 72 6f 6d 65 2e 65 78 65 2a 32 33 34 35 65 78 70 6c 6f 72 65 72 2e 65 78 65 2a 74 68 65 77 6f 72 6c 64 2e 65 78 65 2a } //01 00  iexplore.exe*chrome.exe*2345explorer.exe*theworld.exe*
		$a_03_4 = {73 00 75 00 6e 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 90 02 10 67 00 6f 00 6d 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 63 00 6e 00 90 02 10 6a 00 64 00 2e 00 63 00 6f 00 6d 00 90 02 10 74 00 6d 00 61 00 6c 00 6c 00 90 02 10 64 00 65 00 74 00 61 00 69 00 6c 00 90 02 10 74 00 61 00 6f 00 62 00 61 00 6f 00 90 00 } //02 00 
		$a_03_5 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 15 90 01 03 00 73 1c 8b 85 90 01 03 ff 03 45 f8 0f be 08 83 f1 90 01 01 8b 95 90 01 03 ff 03 55 f8 88 0a eb d0 90 00 } //00 00 
		$a_00_6 = {5d 04 00 00 } //e0 cd 
	condition:
		any of ($a_*)
 
}