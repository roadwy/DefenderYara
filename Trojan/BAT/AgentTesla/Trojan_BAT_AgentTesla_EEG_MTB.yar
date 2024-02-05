
rule Trojan_BAT_AgentTesla_EEG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 07 16 73 90 01 03 0a 0d 03 8e 69 8d 90 01 03 01 13 04 09 11 04 16 03 8e 69 6f 90 01 03 0a 13 05 11 04 11 05 28 90 01 03 2b 28 90 01 03 2b 13 06 de 28 90 00 } //01 00 
		$a_01_1 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //01 00 
		$a_01_2 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EEG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {e3 02 e3 02 e1 02 04 03 d2 02 e1 02 e4 02 14 03 d2 02 e0 02 e3 02 15 03 01 03 f0 02 e0 02 17 03 ce 02 e7 02 e5 02 f0 02 eb 02 ea 02 ed 02 e2 02 ea 02 c9 02 cd 02 cd 02 d6 02 03 03 e9 02 cd 02 f7 02 } //01 00 
		$a_01_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}