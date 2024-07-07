
rule TrojanDownloader_BAT_AgentTesla_ERZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ERZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {0c 16 2d 12 08 06 6f 90 01 03 0a 00 16 2d 07 06 6f 90 01 03 0a 0d 09 13 04 17 2c f0 de 2c 02 2b d0 73 90 01 03 0a 2b cb 28 90 01 03 0a 2b c6 90 00 } //10
		$a_03_1 = {0c 08 06 6f 90 01 03 0a 06 6f 90 01 03 0a 0d 09 13 04 de 0a 90 09 17 00 03 73 90 01 03 0a 28 90 01 03 0a 0b 07 6f 90 01 03 0a 6f 90 01 03 0a 90 00 } //10
		$a_01_2 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 2d 00 74 00 20 00 31 00 35 00 20 00 2d 00 6e 00 6f 00 62 00 72 00 65 00 61 00 6b 00 20 00 26 00 26 00 20 00 70 00 69 00 6e 00 67 00 } //1 /c timeout -t 15 -nobreak && ping
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}