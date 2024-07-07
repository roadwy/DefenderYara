
rule TrojanDownloader_BAT_AgentTesla_DNO_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.DNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 67 00 53 00 76 00 63 00 73 00 } //1 RegSvcs
		$a_01_1 = {30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 000webhostapp.com
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {52 00 55 00 4e 00 4e 00 4e 00 4e 00 } //1 RUNNNN
		$a_01_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_6 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}