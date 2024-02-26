
rule Trojan_BAT_AgentTesla_PTHU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 bd 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 06 fe 0c 01 00 6f 28 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}