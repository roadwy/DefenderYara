
rule PWS_Win32_OnLineGames_ND{
	meta:
		description = "PWS:Win32/OnLineGames.ND,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 74 53 61 6c 6f 6f 6e 2e 65 78 65 } //01 00  GtSaloon.exe
		$a_01_1 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_01_2 = {59 66 3d 6f 6b 74 22 66 3d 75 70 74 } //01 00  Yf=okt"f=upt
		$a_01_3 = {72 73 61 65 6e 68 2e 64 72 73 61 65 6e 68 2e 64 6c 6c } //01 00  rsaenh.drsaenh.dll
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_5 = {78 00 75 00 6c 00 2e 00 64 00 6c 00 6c 00 } //05 00  xul.dll
		$a_01_6 = {25 25 25 30 32 58 00 00 3b 00 00 00 43 6f 6d 6d 75 6e 69 63 61 74 65 2e 64 6c 6c 00 42 61 73 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}