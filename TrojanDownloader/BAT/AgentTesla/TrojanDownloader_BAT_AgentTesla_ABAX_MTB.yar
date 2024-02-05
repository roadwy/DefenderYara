
rule TrojanDownloader_BAT_AgentTesla_ABAX_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 11 04 2b 09 06 18 6f 90 01 03 0a 2b 07 6f 90 01 03 0a 2b f0 02 0c 2b 04 13 04 2b e3 06 6f 90 01 03 0a 08 16 08 8e 69 6f 90 01 03 0a 13 05 de 0e 90 00 } //01 00 
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00 
		$a_01_2 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {47 65 74 42 79 74 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}