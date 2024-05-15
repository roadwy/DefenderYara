
rule Trojan_BAT_AgentTesla_RDBD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 6f 52 00 00 0a 0c 08 06 16 06 8e 69 6f 53 00 00 0a 0d 09 } //00 00 
	condition:
		any of ($a_*)
 
}