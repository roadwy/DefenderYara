
rule TrojanDownloader_BAT_AgentTesla_LLB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {40 31 37 39 2e 34 33 2e 31 38 37 2e 31 33 31 40 } //1 @179.43.187.131@
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}