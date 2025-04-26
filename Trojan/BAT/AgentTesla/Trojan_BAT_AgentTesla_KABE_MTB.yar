
rule Trojan_BAT_AgentTesla_KABE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 08 8e 69 6a 5d d4 91 61 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 ?? 00 00 58 13 08 11 07 07 8e 69 6a 5d 13 09 11 08 20 00 ?? 00 00 5d 13 0a 07 11 09 d4 11 0a d2 9c 11 07 17 6a 58 13 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}