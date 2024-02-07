
rule Trojan_BAT_AgentTesla_KGZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f 90 01 03 0a 06 20 80 00 00 00 6f 90 01 03 0a 02 7b 90 01 03 04 02 7b 90 01 03 04 20 90 01 04 73 90 01 03 0a 0b 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 06 17 6f 90 01 03 0a 03 06 6f 90 01 03 0a 17 73 90 01 03 0a 0c 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_01_4 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 } //00 00  GetManifestResource
	condition:
		any of ($a_*)
 
}