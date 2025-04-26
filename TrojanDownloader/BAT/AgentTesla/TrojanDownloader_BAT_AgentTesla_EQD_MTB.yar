
rule TrojanDownloader_BAT_AgentTesla_EQD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 91 6f ?? ?? ?? 0a 08 25 17 59 0c 16 fe 02 0d 09 2d eb } //1
		$a_03_1 = {06 11 04 16 11 05 6f ?? ?? ?? 0a 08 11 04 16 09 6f ?? ?? ?? 0a 25 13 05 16 fe 03 13 07 11 07 2d df } //1
		$a_01_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_3 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 HttpWebResponse
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}