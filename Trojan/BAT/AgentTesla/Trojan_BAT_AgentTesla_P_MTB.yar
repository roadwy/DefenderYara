
rule Trojan_BAT_AgentTesla_P_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.P!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 28 00 00 0a 20 68 02 a9 fc 28 3c 01 00 06 6f 29 00 00 0a 1e 8d 1a 00 00 01 17 73 2a 00 00 0a 0c 73 2b 00 00 0a 0a 06 08 1f 10 6f 2c 00 00 0a 6f 2d 00 00 0a 06 08 1f 10 6f 2c 00 00 0a 6f 2e 00 00 0a 06 6f 2f 00 00 0a 03 16 03 8e 69 6f 30 00 00 0a } //10
		$a_01_1 = {46 72 6f 6d 41 72 67 62 } //1 FromArgb
		$a_01_2 = {67 65 74 5f 53 61 76 65 4d 79 53 65 74 74 69 6e 67 73 4f 6e 45 78 69 74 } //1 get_SaveMySettingsOnExit
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b 00 43 6f 70 79 } //1 牃慥整敄牣灹潴r牔湡晳牯䙭湩污求捯k潃祰
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}