
rule Trojan_BAT_AgentTesla_SH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 57 00 00 0a 72 ed 06 00 70 6f 58 00 00 0a 11 04 1f 16 5d 91 61 13 09 11 09 07 11 04 17 58 09 5d 91 59 20 00 01 00 00 58 13 0a 07 11 08 11 0a 20 00 01 00 00 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_SH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 1f 16 5d 13 06 06 17 58 13 07 07 11 07 07 8e 69 5d 91 13 08 09 11 06 91 13 09 07 06 91 11 09 61 13 0a 07 06 11 0a 11 08 59 20 00 01 00 00 58 d2 9c 07 06 07 06 91 d2 9c 06 17 58 0a 06 11 04 32 be } //00 00 
	condition:
		any of ($a_*)
 
}