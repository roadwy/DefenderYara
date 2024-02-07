
rule Worm_Win32_Autorun_YB{
	meta:
		description = "Worm:Win32/Autorun.YB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6d 79 64 6f 77 6e 2e 61 73 70 3f 76 65 72 3d 30 38 31 30 90 02 02 26 74 67 69 64 3d 90 02 10 26 61 64 64 72 65 73 73 3d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 90 00 } //0a 00 
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 6d 79 64 6f 77 6e 2e 61 73 70 } //01 00  C:\WINDOWS\mydown.asp
		$a_00_2 = {53 68 75 69 4e 69 75 2e 65 78 65 } //01 00  ShuiNiu.exe
		$a_00_3 = {71 71 6d 2e 65 78 65 } //00 00  qqm.exe
	condition:
		any of ($a_*)
 
}