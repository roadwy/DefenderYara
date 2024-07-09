
rule TrojanDownloader_BAT_AgentTesla_ABM_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {26 06 8e 69 1d 2d 09 26 2b 12 0a 2b eb 0b 2b f1 0c 2b f5 90 0a 2a 00 02 72 57 ?? ?? 70 28 0b ?? ?? 06 1a 2d 13 26 73 34 ?? ?? 0a 1b 2d 0d } //2
		$a_01_1 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //1 set_SecurityProtocol
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule TrojanDownloader_BAT_AgentTesla_ABM_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 06 6f 18 ?? ?? 0a 0d 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 02 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f ?? ?? ?? 0a dc } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}
rule TrojanDownloader_BAT_AgentTesla_ABM_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {a2 09 17 7e ?? ?? ?? 0a a2 09 18 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a a2 09 13 04 08 } //3
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_4 = {43 00 41 00 63 00 63 00 50 00 72 00 6f 00 70 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 43 00 6c 00 61 00 73 00 73 00 2e 00 49 00 41 00 63 00 63 00 50 00 72 00 6f 00 70 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 CAccPropServicesClass.IAccPropServer
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}