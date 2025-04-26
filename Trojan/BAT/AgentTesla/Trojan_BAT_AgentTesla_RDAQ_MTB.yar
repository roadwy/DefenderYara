
rule Trojan_BAT_AgentTesla_RDAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 d1 6f 07 00 00 0a 26 08 17 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}