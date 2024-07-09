
rule TrojanDownloader_BAT_AgentTesla_ABKF_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 13 01 38 ?? ?? ?? 00 dd ?? ?? ?? 00 26 90 0a 30 00 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 2b 28 } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}