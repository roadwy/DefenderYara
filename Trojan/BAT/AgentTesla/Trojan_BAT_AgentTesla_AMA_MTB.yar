
rule Trojan_BAT_AgentTesla_AMA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 50 2b 51 2b 52 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}