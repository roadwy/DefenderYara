
rule Trojan_BAT_AgentTesla_DFZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d de 1e 08 2c 06 08 6f 90 01 03 0a dc 07 2c 06 07 6f 90 01 03 0a dc 06 2c 06 06 6f 90 01 03 0a dc 90 00 } //0a 00 
		$a_03_1 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d dd 90 01 04 08 39 90 01 04 08 6f 90 01 03 0a dc 07 39 90 01 04 07 6f 90 01 03 0a dc 06 39 90 01 04 06 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_4 = {47 5a 69 70 53 74 72 65 61 6d } //00 00  GZipStream
	condition:
		any of ($a_*)
 
}