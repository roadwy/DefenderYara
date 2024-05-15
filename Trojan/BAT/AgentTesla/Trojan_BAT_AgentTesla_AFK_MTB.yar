
rule Trojan_BAT_AgentTesla_AFK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 07 91 13 08 11 06 17 58 08 5d 13 09 07 11 06 91 11 08 61 07 11 09 91 59 20 00 01 00 00 58 13 0a 07 11 06 11 0a 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 aa } //00 00 
	condition:
		any of ($a_*)
 
}