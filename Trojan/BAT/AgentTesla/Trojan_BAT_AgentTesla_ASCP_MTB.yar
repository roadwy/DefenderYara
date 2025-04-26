
rule Trojan_BAT_AgentTesla_ASCP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 44 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 11 05 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 11 05 15 58 13 05 11 05 16 2f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}