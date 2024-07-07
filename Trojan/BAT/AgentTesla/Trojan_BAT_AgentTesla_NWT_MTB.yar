
rule Trojan_BAT_AgentTesla_NWT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 75 0f 00 00 95 e0 95 7e 31 00 00 04 20 7b 0a 00 00 95 61 7e 31 00 00 04 20 46 04 00 00 95 2e 03 17 2b 01 16 58 7e 21 00 00 04 7e 31 00 00 04 20 86 0a 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}