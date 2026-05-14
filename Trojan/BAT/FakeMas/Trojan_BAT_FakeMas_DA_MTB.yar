
rule Trojan_BAT_FakeMas_DA_MTB{
	meta:
		description = "Trojan:BAT/FakeMas.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_03_0 = {5c 67 68 6f 73 74 5c 4c 6f 61 64 65 72 5c 6f 62 6a 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6e 65 74 [0-0f] 5c 4c 6f 61 64 65 72 2e 70 64 62 } //20
		$a_81_1 = {49 6e 76 6f 6b 65 42 6f 77 49 6e 6e 53 6b 69 } //1 InvokeBowInnSki
		$a_81_2 = {44 4c 4c 46 72 6f 6d 4d 65 6d 6f 72 79 } //1 DLLFromMemory
		$a_81_3 = {4c 6f 61 64 65 72 2e 64 6c 6c } //1 Loader.dll
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=23
 
}