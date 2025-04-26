
rule Trojan_BAT_AgentTesla_SLO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 6f 75 01 00 0a 02 8e 69 09 da 28 b6 00 00 0a 13 05 03 02 09 11 05 07 16 6f 76 01 00 0a 13 06 08 07 16 11 06 6f 77 01 00 0a 00 09 11 05 d6 0d 00 09 02 8e 69 fe 04 13 07 11 07 2d c3 } //1
		$a_81_1 = {48 61 67 68 61 7a 69 6e 65 74 61 6b 2e 52 65 73 6f 75 72 63 65 73 } //1 Haghazinetak.Resources
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_SLO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {08 09 a3 06 00 00 1b 13 04 11 04 16 06 07 11 04 8e 69 28 3c 00 00 0a 07 11 04 8e 69 58 0b 09 17 58 0d 09 08 8e 69 32 d8 } //2
		$a_81_1 = {24 65 62 65 31 39 33 66 62 2d 65 37 64 30 2d 34 61 66 34 2d 61 39 35 33 2d 34 62 66 32 36 39 38 36 31 34 37 62 } //1 $ebe193fb-e7d0-4af4-a953-4bf26986147b
		$a_81_2 = {56 66 75 71 7a 6f 68 6f 64 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Vfuqzohod.Properties
		$a_81_3 = {44 70 6a 6a 78 65 6e } //1 Dpjjxen
	condition:
		((#a_00_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}