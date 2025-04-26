
rule Trojan_BAT_AgentTesla_JHX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 6e 17 6a d6 20 ?? ?? ?? 00 6a 5f b8 0c 09 11 05 08 84 95 d7 6e 20 ?? ?? ?? 00 6a 5f b8 0d 11 05 08 84 95 13 04 11 05 08 84 11 05 09 84 95 9e 11 05 09 84 11 04 9e 11 06 11 08 02 11 08 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 ?? ?? ?? 00 6a 5f b7 95 61 86 9c 11 08 17 d6 13 08 } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}