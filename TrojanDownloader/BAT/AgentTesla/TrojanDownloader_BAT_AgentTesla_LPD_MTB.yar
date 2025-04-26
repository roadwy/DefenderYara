
rule TrojanDownloader_BAT_AgentTesla_LPD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {56 56 59 55 59 44 55 59 46 55 46 48 48 4a 46 4a } //1 VVYUYDUYFUFHHJFJ
		$a_81_1 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d } //1 000webhostapp.com
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_4 = {76 34 2e 30 2e 33 30 33 31 39 5c 74 68 65 64 65 76 69 6c 63 6f 64 65 72 2e 65 78 65 } //1 v4.0.30319\thedevilcoder.exe
		$a_01_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_6 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}