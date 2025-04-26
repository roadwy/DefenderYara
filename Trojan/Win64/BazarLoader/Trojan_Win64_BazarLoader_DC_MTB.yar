
rule Trojan_Win64_BazarLoader_DC_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
		$a_81_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //3 PluginInit
		$a_81_2 = {52 75 6e 4f 62 6a 65 63 74 } //3 RunObject
		$a_81_3 = {42 6d 74 70 7a 68 6c 44 68 65 64 61 78 74 43 73 64 75 70 64 79 77 62 61 62 } //3 BmtpzhlDhedaxtCsdupdywbab
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=12
 
}