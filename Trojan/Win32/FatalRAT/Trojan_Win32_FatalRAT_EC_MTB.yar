
rule Trojan_Win32_FatalRAT_EC_MTB{
	meta:
		description = "Trojan:Win32/FatalRAT.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4b 65 79 62 6f 61 72 64 4d 61 6e 61 67 65 72 } //1 KeyboardManager
		$a_81_1 = {44 6f 63 6b 69 6e 67 4d 61 6e 61 67 65 72 73 } //1 DockingManagers
		$a_81_2 = {52 65 73 74 61 72 74 42 79 52 65 73 74 61 72 74 4d 61 6e 61 67 65 72 3a } //1 RestartByRestartManager:
		$a_81_3 = {53 68 65 6c 6c 43 6f 64 65 4c 6f 61 64 65 72 2e 70 64 62 } //1 ShellCodeLoader.pdb
		$a_81_4 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 31 2e 62 69 6e } //1 WINDOWS\system32\1.bin
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}