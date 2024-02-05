
rule Trojan_BAT_AgentTesla_MAAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 5d 13 09 07 09 5b 13 0a 08 11 09 11 0a 6f 90 01 01 00 00 0a 13 0c 11 05 11 04 12 0c 28 90 01 01 00 00 0a 9c 11 04 17 58 13 04 07 17 58 0b 07 09 11 06 5a 32 cd 90 00 } //01 00 
		$a_01_1 = {20 01 e8 00 00 8d 06 00 00 01 13 05 06 } //00 00 
	condition:
		any of ($a_*)
 
}