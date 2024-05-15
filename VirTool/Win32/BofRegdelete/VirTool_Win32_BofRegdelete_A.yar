
rule VirTool_Win32_BofRegdelete_A{
	meta:
		description = "VirTool:Win32/BofRegdelete.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 67 44 65 6c 65 74 65 4b 65 79 56 61 6c 75 65 41 } //01 00  RegDeleteKeyValueA
		$a_01_1 = {42 4f 46 5f 54 45 53 54 } //01 00  BOF_TEST
		$a_01_2 = {44 65 6c 65 74 69 6e 67 20 72 65 67 69 73 74 72 79 20 6b 65 79 } //01 00  Deleting registry key
		$a_01_3 = {64 65 6c 65 74 65 5f 72 65 67 6b 65 79 20 66 61 69 6c 65 64 } //00 00  delete_regkey failed
	condition:
		any of ($a_*)
 
}