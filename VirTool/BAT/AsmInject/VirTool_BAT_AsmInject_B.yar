
rule VirTool_BAT_AsmInject_B{
	meta:
		description = "VirTool:BAT/AsmInject.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 73 53 61 6e 64 62 6f 78 69 65 } //1 IsSandboxie
		$a_01_1 = {49 73 4e 6f 72 6d 61 6e 53 61 6e 64 62 6f 78 } //1 IsNormanSandbox
		$a_01_2 = {49 73 53 75 6e 62 65 6c 74 53 61 6e 64 62 6f 78 } //1 IsSunbeltSandbox
		$a_01_3 = {49 73 41 6e 75 62 69 73 53 61 6e 64 62 6f 78 } //1 IsAnubisSandbox
		$a_01_4 = {49 73 43 57 53 61 6e 64 62 6f 78 } //1 IsCWSandbox
		$a_01_5 = {49 73 57 69 72 65 73 68 61 72 6b } //1 IsWireshark
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}