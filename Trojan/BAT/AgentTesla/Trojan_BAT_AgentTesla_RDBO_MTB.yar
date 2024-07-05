
rule Trojan_BAT_AgentTesla_RDBO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 06 06 6f 1b 00 00 0a 06 6f 1c 00 00 0a 6f 1d 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}