
rule Trojan_BAT_AgentTesla_AMBT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 91 13 06 11 04 07 1f 16 5d 6f ?? 00 00 0a d2 13 07 06 07 17 58 06 8e 69 5d 91 13 08 11 06 11 07 61 11 08 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 09 06 08 11 09 d2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}