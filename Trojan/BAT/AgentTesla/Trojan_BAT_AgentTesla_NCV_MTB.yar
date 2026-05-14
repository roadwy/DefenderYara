
rule Trojan_BAT_AgentTesla_NCV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 02 09 91 07 09 07 8e 69 5d 91 61 d2 9c 08 09 91 2d 0b 08 09 09 20 ff 00 00 00 5d d2 9c 09 17 58 0d 09 1f 20 32 d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_NCV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 07 11 04 91 08 11 04 08 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1 } //2
		$a_81_1 = {43 61 6c 6c 42 79 4e 61 6d 65 } //1 CallByName
		$a_81_2 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}