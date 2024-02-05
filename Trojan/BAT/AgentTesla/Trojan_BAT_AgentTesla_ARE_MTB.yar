
rule Trojan_BAT_AgentTesla_ARE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {16 0b 11 04 06 07 90 01 05 13 05 11 05 90 01 05 13 06 09 08 11 06 b4 9c 07 17 d6 0b 07 16 31 de 08 17 d6 0c 06 17 d6 0a 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}