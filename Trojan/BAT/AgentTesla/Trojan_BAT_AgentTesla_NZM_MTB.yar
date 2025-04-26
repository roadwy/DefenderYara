
rule Trojan_BAT_AgentTesla_NZM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 11 04 91 11 01 61 11 00 11 03 91 61 13 09 } //1
		$a_01_1 = {39 63 38 64 37 63 66 65 65 65 64 61 } //1 9c8d7cfeeeda
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NZM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 00 69 00 65 00 73 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //1 Pies.White
		$a_01_1 = {53 70 6c 69 74 } //1 Split
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_NZM_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 64 39 63 32 30 66 38 30 2d 38 31 38 61 2d 34 61 30 35 2d 62 63 62 36 2d 63 37 39 36 61 62 32 38 36 34 30 39 } //10 $d9c20f80-818a-4a05-bcb6-c796ab286409
		$a_01_1 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}