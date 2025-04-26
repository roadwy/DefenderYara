
rule Trojan_BAT_AgentTesla_ABCE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {18 9a 20 b3 0b 00 00 95 9e 7e 26 00 00 04 7e 20 00 00 04 18 9a 20 84 0e 00 00 95 61 80 26 00 00 04 38 6a 09 00 00 7e 26 00 00 04 7e 20 00 00 04 18 9a 20 f0 10 00 00 07 0c 95 40 7c 02 00 00 7e 26 00 00 04 7e 05 00 00 04 7e 20 00 00 04 18 9a 20 67 11 00 00 95 e0 95 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}