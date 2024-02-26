
rule Trojan_BAT_AgentTesla_AMCI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 0c 91 11 09 58 13 0d 07 11 0b 91 13 0e 08 09 1f 16 5d 91 13 0f 11 0e 11 0f 61 13 10 11 10 11 0d 59 13 11 07 11 0b 11 11 11 09 5d d2 9c 09 17 58 0d } //00 00 
	condition:
		any of ($a_*)
 
}