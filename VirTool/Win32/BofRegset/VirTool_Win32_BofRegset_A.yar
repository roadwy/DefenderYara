
rule VirTool_Win32_BofRegset_A{
	meta:
		description = "VirTool:Win32/BofRegset.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 73 65 74 20 72 65 67 6b 65 79 } //1 Successfully set regkey
		$a_01_1 = {42 4f 46 5f 54 45 53 54 } //1 BOF_TEST
		$a_01_2 = {53 65 74 74 69 6e 67 20 72 65 67 69 73 74 72 79 20 6b 65 79 } //1 Setting registry key
		$a_01_3 = {73 65 74 5f 72 65 67 6b 65 79 20 66 61 69 6c 65 64 } //1 set_regkey failed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}