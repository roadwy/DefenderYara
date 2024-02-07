
rule Trojan_Win32_Zloader_AB_MTB{
	meta:
		description = "Trojan:Win32/Zloader.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 3b d6 8b 0c 85 80 9e 0a 10 0f 95 c0 02 c0 32 44 39 2d 24 02 30 44 39 2d 8d 04 12 } //01 00 
		$a_02_1 = {5c 53 65 61 74 5c 70 61 67 65 5c 70 61 70 65 72 5c 42 75 73 79 5c 90 02 02 5c 64 6f 77 6e 5c 57 69 6e 67 5c 57 6f 75 6c 64 2e 70 64 62 90 00 } //01 00 
		$a_81_2 = {3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  :\Windows\iexplore.exe
		$a_00_3 = {20 05 93 19 00 00 00 00 } //01 00 
		$a_81_4 = {49 73 41 73 79 6e 63 4d 6f 6e 69 6b 65 72 } //01 00  IsAsyncMoniker
		$a_81_5 = {43 3a 5c 54 45 4d 50 5c } //01 00  C:\TEMP\
		$a_81_6 = {43 6f 72 45 78 69 74 50 72 6f 63 65 73 73 } //00 00  CorExitProcess
	condition:
		any of ($a_*)
 
}