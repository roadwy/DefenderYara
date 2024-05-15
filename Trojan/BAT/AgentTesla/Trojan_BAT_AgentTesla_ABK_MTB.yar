
rule Trojan_BAT_AgentTesla_ABK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 18 5d 3a 09 00 00 00 06 02 58 0a 38 04 00 00 00 06 02 59 0a 07 17 58 0b 07 03 32 e3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 28 00 00 0a 0a 06 03 16 03 8e 69 6f 90 01 01 00 00 0a 00 06 6f 2a 00 00 0a 00 00 de 05 90 00 } //01 00 
		$a_01_1 = {73 6f 63 6b 65 74 70 72 6f 67 72 61 6d 69 6e 67 2e 52 65 73 6f 75 72 63 65 31 } //01 00  socketprograming.Resource1
		$a_01_2 = {63 33 34 38 33 33 39 64 2d 31 34 32 34 2d 34 34 35 66 2d 61 66 33 35 2d 39 31 62 61 33 61 30 33 34 63 38 65 } //00 00  c348339d-1424-445f-af35-91ba3a034c8e
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 08 2a 28 0a 90 01 02 06 2b f6 28 05 90 01 02 06 2b f1 90 0a 18 00 72 13 90 01 02 70 2b 03 90 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_4 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}