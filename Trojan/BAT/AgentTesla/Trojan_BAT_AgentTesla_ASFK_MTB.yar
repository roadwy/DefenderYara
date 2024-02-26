
rule Trojan_BAT_AgentTesla_ASFK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 90 02 05 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 90 02 05 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 00 } //01 00 
		$a_01_1 = {11 07 07 8e 69 17 59 09 17 58 5a 6a fe 02 16 fe 01 13 08 } //00 00 
	condition:
		any of ($a_*)
 
}