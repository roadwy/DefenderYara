
rule TrojanDownloader_BAT_AgentTesla_EOR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 16 20 00 04 00 00 6f 90 01 03 0a 13 05 07 11 04 16 11 05 6f 90 01 03 0a 00 00 11 05 16 fe 02 13 06 11 06 2d d7 90 00 } //1
		$a_03_1 = {07 06 08 91 6f 90 01 03 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 2d e8 90 00 } //1
		$a_01_2 = {00 47 65 74 4d 65 74 68 6f 64 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}