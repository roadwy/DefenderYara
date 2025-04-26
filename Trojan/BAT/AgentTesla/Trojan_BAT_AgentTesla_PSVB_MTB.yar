
rule Trojan_BAT_AgentTesla_PSVB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 15 58 0d 09 16 2f b6 02 73 48 00 00 0a 7d 18 00 00 04 02 7b 18 00 00 04 6f ?? 00 00 0a 02 28 ?? 00 00 0a 07 28 ?? 00 00 0a 13 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}