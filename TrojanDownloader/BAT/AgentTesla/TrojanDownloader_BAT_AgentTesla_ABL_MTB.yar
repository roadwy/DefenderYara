
rule TrojanDownloader_BAT_AgentTesla_ABL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 0a 2b 07 28 ?? ?? ?? 06 2b eb 06 16 06 8e 69 28 ?? ?? ?? 0a 2b 07 90 0a 21 00 02 72 ?? ?? ?? 70 28 06 } //8
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}
rule TrojanDownloader_BAT_AgentTesla_ABL_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 06 6f 2a ?? ?? 0a 0d 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 02 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 dd ?? ?? ?? 00 08 39 ?? ?? ?? 00 08 6f ?? ?? ?? 0a dc } //5
		$a_03_1 = {07 09 16 11 04 6f ?? ?? ?? 0a 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 3d ?? ?? ?? ff 07 6f ?? ?? ?? 0a 13 05 } //5
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}