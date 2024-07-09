
rule Trojan_BAT_AgentTesla_EXP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 04 17 58 20 00 3a 00 00 5d 91 59 11 03 58 11 03 5d 13 01 20 00 00 00 00 } //1
		$a_03_1 = {11 01 11 00 03 1f 16 5d ?? ?? ?? ?? ?? 61 13 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}