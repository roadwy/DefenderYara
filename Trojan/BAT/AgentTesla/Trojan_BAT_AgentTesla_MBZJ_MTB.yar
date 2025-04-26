
rule Trojan_BAT_AgentTesla_MBZJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {8e 69 6a 5d d4 91 08 11 ?? 69 } //5
		$a_81_1 = {4c 6f 21 21 21 21 21 61 64 } //5 Lo!!!!!ad
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}