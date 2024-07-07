
rule TrojanDownloader_BAT_AgentTesla_ESM_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ESM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 9a 13 07 00 d0 90 01 03 01 28 90 01 03 0a 14 11 07 28 90 01 03 0a 13 08 11 08 16 8d 90 01 03 01 6f 90 01 03 0a 13 09 00 11 06 17 58 90 00 } //1
		$a_03_1 = {06 07 02 07 91 6f 90 01 03 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 90 00 } //1
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}