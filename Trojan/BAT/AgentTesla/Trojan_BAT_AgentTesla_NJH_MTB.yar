
rule Trojan_BAT_AgentTesla_NJH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 27 00 00 04 18 9a 7e 07 00 00 04 20 97 12 00 00 95 e0 95 7e 07 00 00 04 20 ce 00 00 00 95 61 7e 07 00 00 04 20 a5 04 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}