
rule Trojan_BAT_AgentTesla_EQX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 04 05 5d 03 04 05 5d 91 02 04 1f 16 5d 90 01 05 61 90 01 05 03 04 17 58 05 5d 91 90 01 05 59 20 00 01 00 00 58 20 00 01 00 00 5d 90 00 } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}