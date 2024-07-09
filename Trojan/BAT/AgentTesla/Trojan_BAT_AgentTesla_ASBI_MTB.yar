
rule Trojan_BAT_AgentTesla_ASBI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 06 2b 23 00 08 11 06 18 6f ?? 00 00 0a 13 07 09 11 06 18 5b 11 07 1f 10 28 ?? 00 00 0a d2 9c 00 11 06 18 58 13 06 11 06 20 02 d0 00 00 fe 04 13 08 11 08 2d ce } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}