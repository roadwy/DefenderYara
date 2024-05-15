
rule Trojan_BAT_AgentTesla_PTJT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {d0 b6 00 00 02 28 90 01 01 00 00 0a 6f 7e 02 00 0a 72 34 06 00 70 6f 8c 02 00 0a 73 af 01 00 0a 25 6f b0 01 00 0a 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}