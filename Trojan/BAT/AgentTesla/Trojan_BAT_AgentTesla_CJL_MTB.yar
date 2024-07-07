
rule Trojan_BAT_AgentTesla_CJL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 09 08 09 91 07 09 1f 10 5d 91 61 9c } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}