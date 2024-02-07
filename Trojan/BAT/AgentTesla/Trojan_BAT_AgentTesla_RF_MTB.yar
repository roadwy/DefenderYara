
rule Trojan_BAT_AgentTesla_RF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 01 13 24 11 24 2c 06 18 13 0a 00 2b 06 00 1f 52 13 0a 00 1f 26 13 0b 11 0b 1f 31 fe 01 13 25 11 25 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 04 1c 62 11 07 58 13 04 11 05 17 58 13 05 11 05 19 3e 90 01 01 ff ff ff 07 08 11 04 1f 10 63 20 90 01 01 00 00 00 5f 28 90 01 01 00 00 0a 9c 08 17 58 0c 07 08 11 04 1e 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 68 00 72 00 69 00 73 00 74 00 69 00 61 00 6e 00 62 00 65 00 6c 00 74 00 72 00 61 00 6e 00 2e 00 63 00 6f 00 2f 00 77 00 70 00 2d 00 61 00 64 00 6d 00 69 00 6e 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 63 00 73 00 73 00 2f 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2f 00 62 00 6f 00 } //01 00  christianbeltran.co/wp-admin/images/css/ground/bo
		$a_01_1 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RF_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {06 07 16 20 90 02 04 6f 90 02 04 0d 09 16 fe 02 13 04 11 04 2c 0c 90 01 01 08 07 16 09 6f 90 02 07 09 16 fe 02 13 05 11 05 2d d0 90 00 } //01 00 
		$a_81_1 = {47 5a 49 44 45 4b 4b 4b 4b } //01 00  GZIDEKKKK
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {50 72 69 6d 65 72 } //01 00  Primer
		$a_81_4 = {44 45 53 5f 44 65 63 72 79 70 74 } //00 00  DES_Decrypt
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RF_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {09 11 04 9a 13 05 00 11 05 11 05 6f 1e 00 00 06 16 fe 01 6f 1f 00 00 06 00 00 11 04 17 58 13 04 11 04 09 8e 69 32 d9 } //01 00 
		$a_01_1 = {68 00 6b 00 6b 00 7a 00 75 00 77 00 6c 00 31 00 30 00 45 00 54 00 6a 00 2b 00 53 00 7a 00 78 00 6d 00 54 00 4c 00 6c 00 79 00 77 00 3d 00 3d 00 } //01 00  hkkzuwl10ETj+SzxmTLlyw==
		$a_01_2 = {4d 00 61 00 74 00 72 00 69 00 78 00 47 00 72 00 61 00 70 00 68 00 69 00 63 00 73 00 47 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  MatrixGraphicsGenerator.exe
	condition:
		any of ($a_*)
 
}