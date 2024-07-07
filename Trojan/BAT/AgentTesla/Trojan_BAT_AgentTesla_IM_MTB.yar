
rule Trojan_BAT_AgentTesla_IM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {00 01 25 16 02 03 74 90 01 03 1b 0b 12 01 28 b2 00 00 06 0c 07 10 01 08 a2 14 14 14 28 90 01 03 0a 74 90 01 03 01 0a 02 06 72 90 00 } //10
		$a_81_1 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //1 砀硸硸硸硸硸硸硸硸x
		$a_81_2 = {69 6d 69 6d 69 6d 69 6d 69 6d } //1 imimimimim
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_IM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 8d 90 01 03 01 13 04 2b 0b 08 11 04 16 11 05 6f 90 01 03 0a 09 11 04 16 11 04 8e 69 6f 90 01 03 0a 25 13 05 16 30 e2 90 00 } //10
		$a_01_1 = {57 15 a2 21 09 08 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2f 00 00 00 06 00 00 00 02 00 00 00 0b } //1
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_5 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}