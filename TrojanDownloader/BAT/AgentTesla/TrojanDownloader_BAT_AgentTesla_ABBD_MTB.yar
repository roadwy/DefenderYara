
rule TrojanDownloader_BAT_AgentTesla_ABBD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {0d 07 09 6f 90 01 03 0a 07 18 6f 90 01 03 0a 02 13 04 07 6f 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 dd 90 01 03 00 08 39 90 01 03 00 08 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_2 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}