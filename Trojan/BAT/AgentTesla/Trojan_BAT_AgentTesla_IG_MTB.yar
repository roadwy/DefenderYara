
rule Trojan_BAT_AgentTesla_IG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {38 88 02 00 00 90 02 40 38 90 01 03 00 02 7b 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 9e 38 90 01 03 00 02 7b 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 94 9e 38 90 00 } //10
		$a_80_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  1
		$a_80_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //ClassLibrary  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_IG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 06 16 20 00 b0 02 00 8d 90 01 04 a2 06 17 00 20 67 02 00 00 20 4a 02 00 00 28 90 01 04 a2 06 18 06 17 9a 14 90 00 } //1
		$a_81_1 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_81_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_81_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}