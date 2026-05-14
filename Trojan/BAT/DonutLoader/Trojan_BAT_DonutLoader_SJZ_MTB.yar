
rule Trojan_BAT_DonutLoader_SJZ_MTB{
	meta:
		description = "Trojan:BAT/DonutLoader.SJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 53 68 65 6c 6c 63 6f 64 65 } //1 DecryptShellcode
		$a_81_1 = {42 6c 61 6e 64 52 6f 6f 74 6b 69 74 } //1 BlandRootkit
		$a_81_2 = {47 6c 6f 62 61 6c 5c 42 6c 61 6e 64 52 6f 6f 74 6b 69 74 49 6e 73 74 61 6e 63 65 } //1 Global\BlandRootkitInstance
		$a_81_3 = {57 69 6e 53 65 63 55 70 64 61 74 65 } //1 WinSecUpdate
		$a_81_4 = {73 63 2e 65 78 65 } //1 sc.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}