
rule TrojanDownloader_BAT_SnakeKeylogger_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeylogger.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0c 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 00 06 02 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b de ?? 90 0a 48 00 20 ?? ?? ?? 00 2b ?? ?? 2b ?? 28 ?? ?? ?? 0a 2b ?? ?? de ?? 26 ?? ?? de 00 73 } //15
		$a_01_1 = {41 64 64 53 65 63 6f 6e 64 73 } //1 AddSeconds
		$a_01_2 = {44 61 74 65 54 69 6d 65 } //1 DateTime
		$a_01_3 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //1 SecurityProtocol
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_6 = {6f 70 5f 47 72 65 61 74 65 72 54 68 61 6e } //1 op_GreaterThan
		$a_01_7 = {6f 70 5f 4c 65 73 73 54 68 61 6e } //1 op_LessThan
		$a_01_8 = {67 65 74 5f 4e 6f 77 } //1 get_Now
		$a_01_9 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_10 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_11 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=25
 
}