
rule Trojan_BAT_AgentTesla_PSL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 1f b6 0b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b6 00 00 00 22 00 00 00 73 00 00 00 33 01 00 00 d2 00 00 00 } //5
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_01_3 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}