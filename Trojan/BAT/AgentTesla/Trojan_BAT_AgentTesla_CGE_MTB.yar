
rule Trojan_BAT_AgentTesla_CGE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {19 28 e5 6d 73 32 30 32 32 54 72 75 92 8f 32 30 8a 36 54 72 75 6d 70 32 70 32 36 54 72 75 6d 70 } //1
		$a_00_1 = {7c 6a d7 7e 32 84 3b fb 75 ca 74 21 bd 13 64 5a 5f 27 52 05 1f 1f 55 42 53 5b 74 11 14 03 1e 5d } //1
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_5 = {54 72 75 6d 70 32 30 32 36 } //1 Trump2026
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}