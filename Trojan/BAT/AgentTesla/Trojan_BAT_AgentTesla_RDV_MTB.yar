
rule Trojan_BAT_AgentTesla_RDV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 18 6f 42 00 00 0a 20 03 02 00 00 28 43 00 00 0a 13 05 08 11 05 6f ?? ?? ?? ?? 09 18 58 0d 09 07 6f 45 00 00 0a fe 04 13 06 11 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}