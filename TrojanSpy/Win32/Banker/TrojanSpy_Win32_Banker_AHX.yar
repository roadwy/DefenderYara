
rule TrojanSpy_Win32_Banker_AHX{
	meta:
		description = "TrojanSpy:Win32/Banker.AHX,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 02 00 "
		
	strings :
		$a_02_0 = {5d 5b 30 2d 39 5d 7b 31 90 01 01 7d 90 00 } //02 00 
		$a_00_1 = {38 36 2e 35 35 2e 32 30 36 2e 31 37 30 } //02 00  86.55.206.170
		$a_00_2 = {47 45 54 20 2f 73 65 74 73 2e 74 78 74 } //02 00  GET /sets.txt
		$a_00_3 = {52 45 47 45 58 45 4e 44 } //02 00  REGEXEND
		$a_00_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 47 00 65 00 6e 00 65 00 72 00 69 00 63 00 20 00 46 00 69 00 6c 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00  Windows Generic File Service
		$a_00_5 = {5c 6d 73 76 63 72 36 34 2e 64 6c 6c } //01 00  \msvcr64.dll
		$a_00_6 = {5c 64 79 6e 70 61 67 65 66 69 6c 65 2e 73 79 73 } //00 00  \dynpagefile.sys
	condition:
		any of ($a_*)
 
}