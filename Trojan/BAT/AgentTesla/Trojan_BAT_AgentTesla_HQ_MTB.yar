
rule Trojan_BAT_AgentTesla_HQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 74 75 62 2e 52 65 73 6f 75 72 63 65 73 } //1 Stub.Resources
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 52 75 6e 50 45 } //1 ClassLibrary1.RunPE
		$a_81_2 = {2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2e 70 68 70 3f 69 3d } //1 //pastebin.com/raw.php?i=
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_6 = {49 6e 6a 65 63 74 } //1 Inject
		$a_81_7 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}