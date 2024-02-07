
rule Trojan_BAT_AgentTesla_MZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {1c 9a 0b 07 19 8d 90 01 02 00 01 25 16 7e 90 01 02 00 04 a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 28 90 01 02 00 0a 26 90 00 } //01 00 
		$a_80_1 = {41 74 68 6c 65 74 69 63 43 6c 75 62 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //AthleticClubManagementSystem.Resources  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 37 34 63 64 62 65 30 37 2d 61 39 35 62 2d 34 38 31 61 2d 39 64 38 35 2d 35 35 34 36 65 64 36 31 35 34 64 38 } //01 00  $74cdbe07-a95b-481a-9d85-5546ed6154d8
		$a_81_1 = {52 65 63 6f 72 64 42 67 79 53 79 73 74 65 6d 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  RecordBgySystem.My.Resources
		$a_81_2 = {67 65 74 5f 5f 41 6e 79 5f 62 6c 6f 74 74 65 72 5f 72 65 63 6f 72 64 5f } //01 00  get__Any_blotter_record_
		$a_81_3 = {66 72 6d 52 62 69 5f 4c 6f 61 64 } //01 00  frmRbi_Load
		$a_81_4 = {67 65 74 5f 6c 62 6c 54 6f 74 61 6c 43 65 72 66 } //01 00  get_lblTotalCerf
		$a_81_5 = {43 65 72 66 44 69 61 6c 6f 67 64 65 6c 65 74 65 } //00 00  CerfDialogdelete
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MZ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 05 09 11 05 09 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 09 11 05 09 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 09 17 6f 90 01 03 0a 00 08 09 6f 90 01 03 0a 17 73 90 01 03 0a 13 06 90 02 03 11 06 02 16 02 8e 69 6f 90 01 03 0a 00 11 06 6f 90 01 03 0a 90 02 04 de 0d 90 00 } //01 00 
		$a_01_1 = {66 73 61 66 73 61 66 73 61 66 61 } //01 00  fsafsafsafa
		$a_01_2 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {63 6d 69 6e 75 74 65 5f 4c 6f 61 64 } //01 00  cminute_Load
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_6 = {61 00 66 00 61 00 73 00 66 00 73 00 61 00 66 00 73 00 61 00 66 00 73 00 61 00 66 00 73 00 61 00 66 00 61 00 73 00 41 00 46 00 53 00 41 00 46 00 } //00 00  afasfsafsafsafsafasAFSAF
	condition:
		any of ($a_*)
 
}