
rule Trojan_BAT_AgentTesla_CNS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {00 49 49 49 49 49 49 49 49 49 49 49 33 00 } //1 䤀䥉䥉䥉䥉䥉3
		$a_01_1 = {00 5a 33 33 33 33 33 33 33 33 33 33 33 00 } //1 娀㌳㌳㌳㌳㌳3
		$a_01_2 = {00 5a 34 34 34 34 34 34 34 34 34 34 34 34 34 00 } //1 娀㐴㐴㐴㐴㐴㐴4
		$a_01_3 = {00 5a 36 36 36 36 36 36 36 36 36 36 36 36 36 00 } //1 娀㘶㘶㘶㘶㘶㘶6
		$a_01_4 = {00 5a 36 37 34 34 34 34 34 34 34 34 34 34 34 34 00 } //1
		$a_01_5 = {00 5a 38 38 38 38 38 38 38 38 38 38 38 38 38 38 38 38 00 } //1
		$a_01_6 = {00 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 33 33 33 33 33 33 33 33 00 } //1
		$a_01_7 = {54 6f 55 49 6e 74 33 32 } //1 ToUInt32
		$a_01_8 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 GetMethod
		$a_01_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_10 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_11 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}