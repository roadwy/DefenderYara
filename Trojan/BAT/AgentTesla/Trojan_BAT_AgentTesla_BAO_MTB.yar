
rule Trojan_BAT_AgentTesla_BAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 9a 20 ff 06 00 00 95 34 03 16 2b 01 17 17 59 11 34 16 9a 20 d3 10 00 00 95 5f 11 34 16 9a 20 88 08 00 00 95 61 58 13 2a 38 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}