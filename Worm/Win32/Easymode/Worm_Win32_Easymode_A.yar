
rule Worm_Win32_Easymode_A{
	meta:
		description = "Worm:Win32/Easymode.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 c4 10 66 81 7d b8 4d 5a 74 } //03 00 
		$a_03_1 = {0f be 45 d4 83 f8 61 74 90 01 01 0f be 55 d4 83 fa 41 74 90 00 } //01 00 
		$a_01_2 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_3 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d } //01 00  shell\explore\Command=
		$a_00_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}