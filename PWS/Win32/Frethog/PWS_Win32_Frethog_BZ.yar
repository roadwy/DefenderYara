
rule PWS_Win32_Frethog_BZ{
	meta:
		description = "PWS:Win32/Frethog.BZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 02 04 02 0d 00 00 64 00 "
		
	strings :
		$a_00_0 = {78 79 75 70 72 69 25 64 2e 64 6c 6c } //64 00  xyupri%d.dll
		$a_00_1 = {45 33 46 34 32 36 46 36 2d 34 32 41 35 2d 41 32 39 45 2d 38 36 33 34 2d 42 43 36 39 34 41 38 38 46 42 37 44 } //64 00  E3F426F6-42A5-A29E-8634-BC694A88FB7D
		$a_00_2 = {00 6d 79 2e 65 78 65 } //64 00 
		$a_00_3 = {46 69 6c 4d 73 67 2e 65 78 65 } //64 00  FilMsg.exe
		$a_00_4 = {54 77 69 73 74 65 72 2e 65 78 65 } //0a 00  Twister.exe
		$a_00_5 = {52 61 76 4d 6f 6e 2e 65 78 65 } //05 00  RavMon.exe
		$a_00_6 = {4d 4e 44 4c 4c } //05 00  MNDLL
		$a_00_7 = {23 33 32 37 37 30 } //05 00  #32770
		$a_00_8 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //05 00  Process32Next
		$a_00_9 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //05 00  Process32First
		$a_01_10 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_11 = {45 78 65 4d 6f 64 75 6c 65 4e 61 6d 65 } //01 00  ExeModuleName
		$a_00_12 = {44 6c 6c 4d 6f 64 75 6c 65 4e 61 6d 65 } //00 00  DllModuleName
	condition:
		any of ($a_*)
 
}