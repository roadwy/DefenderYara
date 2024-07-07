
rule Trojan_BAT_AgentTesla_LDC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 07 11 0b 6f 90 01 03 0a 1d 62 d2 11 07 11 0b 17 d6 6f 90 01 03 0a 1c 62 d2 58 86 11 07 11 0b 18 d6 6f 90 01 03 0a 1b 62 d2 58 86 11 07 11 0b 19 d6 6f 90 00 } //1
		$a_03_1 = {1a 62 d2 58 86 11 07 11 0b 1a d6 6f 90 01 03 0a 19 62 d2 58 86 11 07 11 0b 1b d6 6f 90 01 03 0a 18 62 d2 58 86 11 07 11 0b 1c d6 6f 90 00 } //1
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {44 65 63 6f 64 65 } //1 Decode
		$a_01_4 = {4e 53 65 72 76 65 72 } //1 NServer
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}