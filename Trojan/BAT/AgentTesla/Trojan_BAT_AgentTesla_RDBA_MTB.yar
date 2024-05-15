
rule Trojan_BAT_AgentTesla_RDBA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f e0 00 00 0a 28 62 00 00 06 a2 28 e1 00 00 0a 75 55 00 00 01 0c 08 6f e2 00 00 0a 17 9a 0d } //00 00 
	condition:
		any of ($a_*)
 
}