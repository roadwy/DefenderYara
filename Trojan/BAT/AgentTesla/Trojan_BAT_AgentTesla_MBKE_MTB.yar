
rule Trojan_BAT_AgentTesla_MBKE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 8e 69 5d 02 06 07 06 8e 69 5d 91 11 04 07 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 06 07 17 58 06 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 28 ?? 00 00 06 28 ?? 00 00 0a 9c 07 15 58 0b 07 16 2f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}