
rule Trojan_Win32_BHO_LI{
	meta:
		description = "Trojan:Win32/BHO.LI,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 } //05 00  PendingFileRenameOperations
		$a_01_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //05 00  Internet Explorer\SearchScopes
		$a_01_2 = {72 65 67 73 76 72 33 32 20 2f 73 20 22 25 73 } //05 00  regsvr32 /s "%s
		$a_00_3 = {69 65 62 68 6f 2e 64 6c 6c } //05 00  iebho.dll
		$a_01_4 = {55 70 64 61 74 65 54 69 6d 65 } //05 00  UpdateTime
		$a_01_5 = {68 53 6b 69 6e 4d 75 74 65 78 } //05 00  hSkinMutex
		$a_01_6 = {44 6f 77 6e 57 6f 6d 4d 65 6d } //01 00  DownWomMem
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 6e 61 76 6f 63 74 } //01 00  SOFTWARE\navoct
		$a_01_8 = {69 65 77 6f 70 74 69 6d 65 6d 2e 65 78 65 } //01 00  iewoptimem.exe
		$a_01_9 = {49 45 54 6f 6f 6c 2e 64 6c 6c } //00 00  IETool.dll
	condition:
		any of ($a_*)
 
}