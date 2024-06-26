
rule Trojan_BAT_AgentTesla_ABW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {20 1f 0a 00 00 95 2e 03 16 2b 01 17 7e 25 00 00 04 20 f0 09 00 00 95 5a 7e 25 00 00 04 20 35 0d 00 00 95 58 61 80 26 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABW_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {1f 28 28 38 90 01 02 0a 0c 08 72 7d 90 01 02 70 28 90 01 03 0a 0d 09 28 90 01 03 0a 16 fe 01 13 09 11 09 3a 90 01 03 00 00 09 28 90 01 03 0a 16 9a 0d 09 09 90 00 } //01 00 
		$a_01_1 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //01 00  GetDirectories
		$a_01_2 = {53 6d 74 70 43 6c 69 65 6e 74 } //01 00  SmtpClient
		$a_01_3 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_01_4 = {46 00 69 00 72 00 65 00 46 00 69 00 78 00 } //00 00  FireFix
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABW_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 31 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 7e 90 01 03 04 06 28 90 01 03 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 41 00 72 00 69 00 74 00 68 00 6d 00 65 00 74 00 69 00 63 00 47 00 61 00 6d 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  NetworkArithmeticGame.Properties.Resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABW_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 03 00 "
		
	strings :
		$a_03_0 = {06 07 16 20 00 90 01 02 00 6f 8c 90 01 02 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f 8d 90 01 02 0a 00 00 00 09 16 fe 02 13 05 11 05 2d d0 08 6f 8e 90 01 02 0a 13 06 de 16 90 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {44 65 63 6f 6d 70 72 65 73 73 47 5a 69 70 } //01 00  DecompressGZip
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_5 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //01 00  GetEnumerator
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_7 = {62 79 74 65 73 54 6f 44 65 63 6f 6d 70 72 65 73 73 } //00 00  bytesToDecompress
	condition:
		any of ($a_*)
 
}