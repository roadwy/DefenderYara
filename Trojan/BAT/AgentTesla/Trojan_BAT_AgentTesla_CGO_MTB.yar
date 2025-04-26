
rule Trojan_BAT_AgentTesla_CGO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {34 00 66 00 75 00 67 00 34 00 41 00 74 00 41 00 6e 00 4e 00 49 00 62 00 67 00 42 00 54 00 4d 00 30 00 68 00 56 00 47 00 68 00 70 00 63 00 79 00 42 00 77 00 63 00 6d 00 39 00 6e 00 63 00 6d 00 } //1 4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncm
		$a_00_1 = {5a 00 53 00 42 00 79 00 64 00 57 00 34 00 67 00 61 00 57 00 34 00 67 00 52 00 45 00 39 00 54 00 49 } //1
		$a_81_2 = {54 68 72 65 61 64 50 6f 6f 6c 2e 4c 69 67 68 74 } //1 ThreadPool.Light
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}