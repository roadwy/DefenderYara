
rule TrojanDownloader_BAT_AgentTesla_EPZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 91 6f ?? ?? ?? 0a 08 25 17 59 0c 16 fe 02 0d 09 2d eb } //1
		$a_03_1 = {06 11 04 16 11 05 6f ?? ?? ?? 0a 08 11 04 16 09 6f ?? ?? ?? 0a 25 13 05 16 fe 03 13 07 11 07 2d df } //1
		$a_01_2 = {34 00 35 00 2e 00 31 00 33 00 37 00 2e 00 32 00 32 00 2e 00 31 00 36 00 33 00 } //1 45.137.22.163
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}