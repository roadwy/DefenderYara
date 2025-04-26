
rule VirTool_Win32_BofRegsave_A{
	meta:
		description = "VirTool:Win32/BofRegsave.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 41 20 66 61 69 6c 65 64 } //1 RegOpenKeyExA failed
		$a_01_1 = {52 65 67 44 65 6c 65 74 65 4b 65 79 56 61 6c 75 65 41 20 66 61 69 6c 65 64 } //1 RegDeleteKeyValueA failed
		$a_01_2 = {42 4f 46 5f 54 45 53 54 } //1 BOF_TEST
		$a_01_3 = {44 65 6c 65 74 69 6e 67 20 72 65 67 69 73 74 72 79 20 6b 65 79 } //1 Deleting registry key
		$a_01_4 = {64 65 6c 65 74 65 5f 72 65 67 6b 65 79 20 66 61 69 6c 65 64 } //1 delete_regkey failed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}