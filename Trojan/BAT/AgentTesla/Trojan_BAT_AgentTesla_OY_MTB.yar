
rule Trojan_BAT_AgentTesla_OY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b 02 26 16 28 [0-04] 02 28 [0-04] 28 [0-04] 28 [0-04] 0a 02 06 72 [0-04] 28 [0-04] 28 [0-04] 7d [0-04] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}