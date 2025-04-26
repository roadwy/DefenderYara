
rule TrojanDownloader_BAT_AgentTesla_LTB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 62 75 79 73 72 69 6c 61 6e 6b 61 6e 2e 6c 6b 2f 70 70 2f 43 6f 6e 73 6f 6c 65 41 70 70 } //1 https://buysrilankan.lk/pp/ConsoleApp
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}