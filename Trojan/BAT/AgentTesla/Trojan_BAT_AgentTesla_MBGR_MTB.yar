
rule Trojan_BAT_AgentTesla_MBGR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 dd 08 00 70 1b 8d 90 01 01 00 00 01 25 16 72 f7 08 00 70 72 0d 09 00 70 72 73 07 00 70 28 90 01 01 00 00 0a a2 25 17 20 00 01 00 00 8c 90 01 01 00 00 01 a2 14 14 90 00 } //01 00 
		$a_01_1 = {47 00 65 00 74 00 54 00 79 00 70 00 65 00 73 00 00 09 4c 00 6f 00 61 00 64 00 } //00 00  GetTypesऀLoad
	condition:
		any of ($a_*)
 
}