
rule Trojan_BAT_AgentTesla_BXD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 17 8d 90 01 03 01 25 16 07 6f 90 01 03 0a a2 0d de 1e 08 2c 06 08 6f 90 01 03 0a dc 07 2c 06 07 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_81_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}