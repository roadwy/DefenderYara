
rule Trojan_BAT_AgentTesla_MBZX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 58 02 58 17 59 d3 1e 5a 58 4f 0c } //01 00 
		$a_01_1 = {64 31 33 65 62 36 32 32 32 } //00 00  d13eb6222
	condition:
		any of ($a_*)
 
}