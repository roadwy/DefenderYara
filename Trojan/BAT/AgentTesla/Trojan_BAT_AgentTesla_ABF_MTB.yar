
rule Trojan_BAT_AgentTesla_ABF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {95 6e 31 03 16 2b 01 17 7e 02 00 00 04 18 06 0c 9a 20 81 0b 00 00 95 5a 7e 02 00 00 04 18 9a 20 a7 0d 00 00 95 58 61 81 05 00 00 01 } //02 00 
		$a_01_1 = {95 e0 95 2d 06 16 09 13 08 2b 01 17 7e 1c 01 00 04 17 9a 20 b1 01 00 00 95 5a 7e 1c 01 00 04 17 9a 20 c2 01 00 00 95 58 61 80 18 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 90 01 03 00 6f 90 01 03 0a 0b 07 16 fe 02 13 06 11 06 2c 09 06 09 16 07 6f 90 01 03 0a 07 16 fe 02 13 07 11 07 2d d5 06 6f 90 01 03 0a 13 05 de 0a 90 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {17 da 13 04 16 13 05 11 05 16 fe 01 13 08 11 08 2c 05 38 c8 00 00 00 00 00 72 90 01 04 03 11 05 18 6f 90 01 04 28 90 01 04 28 90 01 04 07 08 6f 90 01 04 28 90 01 04 6a 61 b7 28 90 01 04 28 90 01 04 13 06 90 00 } //03 00 
		$a_80_1 = {53 55 50 45 52 4d 45 } //SUPERME  03 00 
		$a_80_2 = {77 79 62 5f 66 69 67 } //wyb_fig  03 00 
		$a_80_3 = {77 79 70 65 6c 6e 69 6a 5f 73 69 61 74 6b 65 } //wypelnij_siatke  03 00 
		$a_80_4 = {77 79 70 5f 73 69 61 74 6b 61 5f 6c 65 67 } //wyp_siatka_leg  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABF_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {12 17 28 4d 90 01 02 0a 73 4e 90 01 02 0a 0b d0 0e 90 01 02 02 28 19 90 01 02 0a 6f 31 90 01 02 0a 72 52 90 01 02 70 6f 4f 90 01 02 0a 73 50 90 01 02 0a 0c 08 6f 4a 90 01 02 0a 16 6a 6f 4b 90 01 02 0a 08 08 90 0a 43 00 7e 27 90 01 02 04 25 13 26 90 00 } //05 00 
		$a_03_1 = {11 07 11 08 61 13 11 11 06 11 0b 11 11 20 ff 90 01 02 00 5f d2 9c 11 06 11 0b 17 58 11 11 20 00 90 01 02 00 5f 1e 64 d2 9c 11 06 90 00 } //01 00 
		$a_01_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_5 = {46 69 6c 65 41 63 63 65 73 73 } //01 00  FileAccess
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}