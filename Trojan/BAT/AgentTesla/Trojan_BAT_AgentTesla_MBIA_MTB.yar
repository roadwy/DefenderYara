
rule Trojan_BAT_AgentTesla_MBIA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 56 00 71 00 51 00 28 06 98 06 cc 06 a9 06 d5 06 31 06 a9 06 48 06 a9 06 48 06 31 06 2f 06 33 06 2a 06 27 06 46 06 28 06 98 06 cc 06 a9 06 d5 06 31 06 a9 06 48 06 a9 06 48 06 31 06 2f 06 33 06 2a 06 27 06 46 06 4d 00 } //01 00 
		$a_01_1 = {a9 06 48 06 31 06 2f 06 33 06 2a 06 27 06 46 06 6e 00 4e 00 49 00 62 00 67 00 42 00 54 00 4d 00 30 00 68 00 56 00 47 00 68 00 70 00 63 00 79 00 42 00 } //00 00 
	condition:
		any of ($a_*)
 
}