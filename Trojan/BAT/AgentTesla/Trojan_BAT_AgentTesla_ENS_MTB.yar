
rule Trojan_BAT_AgentTesla_ENS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 02 8e 69 17 59 91 1f 70 61 } //01 00 
		$a_01_1 = {02 11 04 91 11 01 61 11 09 11 03 91 61 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ENS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ENS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 04 20 00 14 01 00 5d 07 11 04 20 00 14 01 00 5d 91 08 11 04 1f 16 5d 6f 90 01 03 0a 61 07 11 04 17 58 20 00 14 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ENS_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ENS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 30 fe 68 37 47 41 30 4a 78 76 66 8e ae 76 44 f7 35 6a 6e 68 34 47 41 70 4e 78 76 66 71 51 76 44 4f 35 6a 6e 68 34 47 41 30 4e 78 76 66 71 51 } //01 00 
		$a_01_1 = {4e 70 7e 6e b0 94 73 80 5c 36 79 7e a9 f9 4a 8d b2 c8 7e f2 d7 f8 68 ce b7 80 0a 96 1f 25 09 3b 80 f1 4f b8 47 67 40 61 87 81 7a c1 e8 e4 62 bc } //00 00 
	condition:
		any of ($a_*)
 
}