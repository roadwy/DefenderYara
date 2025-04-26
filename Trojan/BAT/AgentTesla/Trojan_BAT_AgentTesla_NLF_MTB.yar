
rule Trojan_BAT_AgentTesla_NLF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {7b 1a 00 00 04 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 07 16 07 8e 69 6f ?? ?? ?? 0a } //5
		$a_01_1 = {31 66 73 69 78 64 74 } //1 1fsixdt
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 5a 61 6d 65 74 6b 61 } //1 downloadZametka
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_NLF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {24 35 62 62 35 65 32 35 61 2d 35 38 61 38 2d 34 63 36 62 2d 38 61 38 39 2d 33 31 32 63 36 65 32 37 36 39 30 37 } //1 $5bb5e25a-58a8-4c6b-8a89-312c6e276907
		$a_01_1 = {69 6e 76 65 73 74 69 67 61 74 69 6f 6e 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 investigation.g.resources
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_4 = {66 72 61 75 64 75 6c 65 6e 74 20 6f 72 20 6d 69 73 6c 65 61 64 69 6e 67 } //1 fraudulent or misleading
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_01_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}