
rule Trojan_BAT_AgentTesla_NFK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 31 33 31 34 36 33 63 38 2d 30 31 32 34 2d 34 38 39 63 2d 39 32 33 63 2d 34 65 38 66 62 38 63 61 36 31 66 37 } //1 $131463c8-0124-489c-923c-4e8fb8ca61f7
		$a_01_1 = {57 5d b6 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 } //1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_NFK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00 19 57 00 5b 00 4f 00 50 00 4e 00 4d 00 4e 00 44 00 56 00 38 00 59 00 39 00 00 19 78 00 63 00 76 00 78 } //1
		$a_01_1 = {76 00 65 00 67 00 65 00 74 00 32 00 31 00 71 00 00 13 49 00 6e 00 63 00 72 00 65 00 6d 00 65 00 6e 00 74 } //1
		$a_81_2 = {56 43 58 4d 55 39 39 } //1 VCXMU99
		$a_81_3 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //1 GetManifestResourceNames
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}