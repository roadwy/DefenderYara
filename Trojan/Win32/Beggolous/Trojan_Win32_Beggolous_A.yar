
rule Trojan_Win32_Beggolous_A{
	meta:
		description = "Trojan:Win32/Beggolous.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 6f 63 61 74 65 41 6e 64 49 6e 69 74 69 61 6c 69 7a 65 53 69 64 } //01 00  AllocateAndInitializeSid
		$a_01_1 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 57 } //01 00  SHGetFolderPathW
		$a_01_2 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 57 } //0a 00  RegSetValueExW
		$a_00_3 = {44 3a 5c 50 72 6f 6a 65 63 74 73 5c 73 72 63 5c 62 79 70 61 73 73 75 61 63 5c 62 72 61 6e 63 68 65 73 5c 52 65 67 54 6f 6f 6c 5c 62 75 69 6c 64 5c 52 65 6c 65 61 73 65 5c 72 65 67 74 6f 6f 6c 2e 70 64 62 } //00 00  D:\Projects\src\bypassuac\branches\RegTool\build\Release\regtool.pdb
	condition:
		any of ($a_*)
 
}