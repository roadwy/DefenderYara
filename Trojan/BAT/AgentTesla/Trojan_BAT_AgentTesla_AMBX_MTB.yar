
rule Trojan_BAT_AgentTesla_AMBX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 0b 91 11 09 58 13 0c 07 11 0a 91 13 0d 11 0d 08 11 08 1f 16 5d 91 61 13 0e 11 0e 11 0c 59 13 0f 07 11 0a 11 0f 11 09 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}