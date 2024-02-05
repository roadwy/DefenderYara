
rule Trojan_BAT_AgentTesla_EQF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 08 11 05 e0 58 0c 08 1f 10 58 4b 13 06 08 1f 14 58 4b 13 07 08 11 05 e0 59 0c 11 06 8d 90 01 03 01 0a 08 11 07 e0 58 0c 06 16 8f 90 01 03 01 90 00 } //01 00 
		$a_01_1 = {11 0c 11 0d 58 08 11 0d 58 47 52 00 11 0d 17 58 13 0d } //00 00 
	condition:
		any of ($a_*)
 
}