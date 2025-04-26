
rule Trojan_BAT_AgentTesla_MBXW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a7 00 a9 00 71 00 51 00 84 25 84 25 4d 00 84 25 84 25 84 25 84 25 45 00 84 25 84 25 84 25 84 25 2f 00 2f 00 38 00 84 25 84 25 4c 00 67 00 84 25 84 25 84 25 84 25 84 25 84 25 84 25 84 25 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}