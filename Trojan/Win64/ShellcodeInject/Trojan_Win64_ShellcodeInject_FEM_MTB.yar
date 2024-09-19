
rule Trojan_Win64_ShellcodeInject_FEM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.FEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 89 6c 24 50 48 c7 44 24 58 0f 00 00 00 c6 44 24 40 00 49 8b 46 10 48 3b c6 0f 82 2f 01 00 00 48 2b c6 41 b8 02 00 00 00 49 3b c0 4c 0f 42 c0 49 8b c6 49 83 7e 18 10 72 03 49 8b 06 } //5
		$a_81_1 = {55 73 61 67 65 3a 20 25 73 20 3c 70 72 6f 63 65 73 73 5f 6e 61 6d 65 3e 20 3c 68 65 78 5f 73 74 72 69 6e 67 3e } //1 Usage: %s <process_name> <hex_string>
		$a_81_2 = {69 6e 65 6a 63 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 69 6e 65 6a 63 74 2e 70 64 62 } //1 inejct\x64\Release\inejct.pdb
	condition:
		((#a_00_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}