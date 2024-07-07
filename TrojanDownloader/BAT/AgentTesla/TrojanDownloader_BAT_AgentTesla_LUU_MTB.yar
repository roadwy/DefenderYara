
rule TrojanDownloader_BAT_AgentTesla_LUU_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 62 75 79 73 72 69 6c 61 6e 6b 61 6e 2e 6c 6b 2f 6b 2f 43 6f 6e 73 6f 6c 65 41 70 70 } //1 https://buysrilankan.lk/k/ConsoleApp
		$a_01_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}