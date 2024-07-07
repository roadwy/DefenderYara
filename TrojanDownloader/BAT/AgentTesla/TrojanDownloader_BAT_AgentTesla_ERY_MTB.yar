
rule TrojanDownloader_BAT_AgentTesla_ERY_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ERY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 25 17 59 0c 16 2d 03 16 fe 02 16 2d 02 0d 09 2d dc 06 6f 90 01 03 0a 0b 07 13 04 1c 2c e1 90 00 } //1
		$a_03_1 = {16 2d fc 20 00 0c 00 00 2b 07 00 1a 2c f2 00 de 0c 28 90 01 03 0a 2b f2 90 00 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}