
rule Trojan_BAT_AgentTesla_GZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 5d 0c 07 09 94 13 04 07 09 07 08 94 9e 07 08 11 04 9e 07 07 09 94 07 08 94 58 20 00 01 00 00 5d 94 13 08 11 06 06 02 06 91 11 08 61 d2 9c 06 17 58 0a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}