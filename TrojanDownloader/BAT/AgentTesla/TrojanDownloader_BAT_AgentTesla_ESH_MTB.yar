
rule TrojanDownloader_BAT_AgentTesla_ESH_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ESH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 91 6f 90 01 03 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 90 00 } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}