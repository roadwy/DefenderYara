
rule Trojan_BAT_AgentTesla_DCP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a de 0a 08 2c 06 08 6f 90 01 03 0a dc 07 6f 90 01 03 0a 0d de 14 07 2c 06 07 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_3 = {43 00 6c 00 61 00 73 00 73 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 } //01 00  ClassLibrary
		$a_01_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}