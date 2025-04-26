
rule Trojan_BAT_AgentTesla_SOL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 0d 11 10 61 13 11 11 07 11 0c d4 11 11 20 ff 00 00 00 5f d2 9c 1f 37 13 15 38 68 f9 } //1
		$a_81_1 = {56 37 47 55 47 34 35 48 30 43 37 35 5a 35 41 45 37 34 38 37 55 51 } //1 V7GUG45H0C75Z5AE7487UQ
		$a_81_2 = {4a 6f 6b 65 6e 70 6f 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Jokenpo.Properties
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SOL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {11 14 11 16 61 13 17 11 07 11 13 d4 11 17 20 ff 00 00 00 5f d2 9c 16 13 1b 2b 25 00 11 17 6e 11 1b 6a 5a 11 16 6e 58 69 20 00 01 00 00 5d 13 1c 11 1c 19 58 1f 40 5d 13 1c 00 11 1b 17 58 13 1b 11 1b 19 fe 04 13 1d 11 1d 2d d0 } //1
		$a_81_1 = {46 37 48 38 41 38 37 35 35 34 42 38 38 38 51 4a 48 35 37 34 45 32 } //1 F7H8A87554B888QJH574E2
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_SOL_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SOL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 b4 00 00 0a 72 0f 0c 00 70 6f b5 00 00 0a 09 1f 16 5d 91 13 04 07 09 91 11 04 61 13 05 09 17 58 08 5d 13 06 07 11 06 91 13 07 20 00 01 00 00 13 08 11 05 11 07 59 11 08 58 11 08 17 59 5f 13 09 07 09 11 09 d2 9c 09 17 58 0d 09 08 32 b1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}