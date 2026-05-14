
rule Trojan_BAT_FakeMas_DB_MTB{
	meta:
		description = "Trojan:BAT/FakeMas.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 65 78 63 6c 75 73 69 6f 6e 20 61 64 64 65 64 20 74 6f 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //20 cmd.exe exclusion added to Windows Defender
		$a_81_1 = {73 76 6d 69 6e 65 72 6c 6f 61 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 svminerloader.Properties.Resources
		$a_81_2 = {44 4c 4c 46 72 6f 6d 4d 65 6d 6f 72 79 } //1 DLLFromMemory
		$a_81_3 = {49 6e 76 6f 6b 65 4d 69 6e 65 72 } //1 InvokeMiner
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=23
 
}