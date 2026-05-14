
rule Trojan_Win64_GoShell_CM_MTB{
	meta:
		description = "Trojan:Win64/GoShell.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {44 65 6c 65 74 65 53 65 6c 66 } //2 DeleteSelf
		$a_01_1 = {53 70 61 77 6e 41 6e 64 49 6e 6a 65 63 74 44 6c 6c } //2 SpawnAndInjectDll
		$a_01_2 = {69 6e 6a 65 63 74 53 65 6c 66 } //2 injectSelf
		$a_01_3 = {65 78 65 63 41 73 6d 49 6e 6a 65 63 74 } //2 execAsmInject
		$a_01_4 = {70 61 72 73 65 43 6f 6d 6d 61 6e 64 53 68 65 6c 6c } //2 parseCommandShell
		$a_01_5 = {47 65 74 4e 65 74 77 6f 72 6b 49 6e 66 6f 72 6d 61 74 69 6f 6e } //2 GetNetworkInformation
		$a_01_6 = {53 74 65 61 6c 54 6f 6b 65 6e } //2 StealToken
		$a_01_7 = {4b 69 6c 6c 50 72 6f 63 65 73 73 } //2 KillProcess
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=10
 
}