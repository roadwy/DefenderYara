
rule Trojan_BAT_AgentTesla_NJF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 36 03 00 00 95 9e 7e 07 00 00 04 7e 21 00 00 04 1c 9a 20 68 04 00 00 95 61 80 07 00 00 04 7e 07 00 00 04 7e 21 00 00 04 1c 9a 20 d5 01 00 00 07 0b 95 40 eb 00 00 00 7e 05 00 00 04 17 9a 18 9a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}