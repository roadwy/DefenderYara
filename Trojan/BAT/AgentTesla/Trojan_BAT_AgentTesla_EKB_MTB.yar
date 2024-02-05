
rule Trojan_BAT_AgentTesla_EKB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 00 09 6f 90 01 03 0a 13 04 16 13 05 2b 60 11 04 11 05 9a 13 06 00 11 06 6f 90 01 03 0a 13 07 16 13 08 2b 3c 11 07 11 08 9a 13 09 00 00 28 90 01 03 06 11 06 72 90 01 03 70 20 00 01 00 00 14 14 14 90 00 } //01 00 
		$a_01_1 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 31 00 39 00 } //00 00 
	condition:
		any of ($a_*)
 
}