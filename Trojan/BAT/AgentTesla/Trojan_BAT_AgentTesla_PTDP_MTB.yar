
rule Trojan_BAT_AgentTesla_PTDP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f c0 01 00 06 6f 30 00 00 0a 7d 38 01 00 04 fe 0c 03 00 fe 0c 02 00 6f be 01 00 06 72 e7 00 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}