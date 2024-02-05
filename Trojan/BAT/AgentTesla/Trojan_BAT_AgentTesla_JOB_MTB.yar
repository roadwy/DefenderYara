
rule Trojan_BAT_AgentTesla_JOB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 04 09 06 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 06 17 58 0a 06 09 6f 90 01 03 0a 18 5b fe 04 13 05 11 05 2d d3 90 00 } //01 00 
		$a_01_1 = {4e 78 74 4d 61 6e 61 67 65 72 56 33 } //00 00 
	condition:
		any of ($a_*)
 
}