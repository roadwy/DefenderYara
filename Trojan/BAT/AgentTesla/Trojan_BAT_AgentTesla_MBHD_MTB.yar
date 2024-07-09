
rule Trojan_BAT_AgentTesla_MBHD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 5c 01 00 0d 2b 43 08 09 08 8e 69 5d 08 09 08 8e 69 5d 91 11 05 09 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 08 09 17 58 08 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}