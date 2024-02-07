
rule PWS_Win32_Frethog_K{
	meta:
		description = "PWS:Win32/Frethog.K,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {5c 73 79 73 74 65 6d 33 32 5c 6d 68 90 01 03 2e 64 6c 6c 90 00 } //01 00 
		$a_01_1 = {6c 69 6e 2e 61 73 70 00 } //01 00 
		$a_01_2 = {57 69 6e 49 6e 65 74 } //01 00  WinInet
		$a_00_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  explorer.exe
		$a_00_4 = {6d 79 2e 65 78 65 } //01 00  my.exe
		$a_00_5 = {57 53 47 41 4d 45 } //00 00  WSGAME
	condition:
		any of ($a_*)
 
}