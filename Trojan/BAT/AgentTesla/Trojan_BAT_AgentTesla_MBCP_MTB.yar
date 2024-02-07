
rule Trojan_BAT_AgentTesla_MBCP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a a2 25 17 03 a2 25 18 02 17 8d 90 01 01 00 00 01 25 16 1e 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a a2 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {62 64 35 61 2d 31 35 33 61 64 31 34 66 33 63 33 35 } //00 00  bd5a-153ad14f3c35
	condition:
		any of ($a_*)
 
}