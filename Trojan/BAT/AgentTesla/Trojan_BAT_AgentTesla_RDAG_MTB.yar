
rule Trojan_BAT_AgentTesla_RDAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 18 6f 6f 00 00 0a 1f 10 28 70 00 00 0a 9c 00 08 18 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}