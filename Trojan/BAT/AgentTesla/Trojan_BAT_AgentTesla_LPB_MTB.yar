
rule Trojan_BAT_AgentTesla_LPB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_81_0 = {54 30 6f 30 57 69 30 6e 30 33 30 32 } //10 T0o0Wi0n0302
		$a_81_1 = {4c 30 6f 30 61 30 64 30 } //10 L0o0a0d0
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_5 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_6 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}