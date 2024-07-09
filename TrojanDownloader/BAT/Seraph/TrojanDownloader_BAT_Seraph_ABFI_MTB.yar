
rule TrojanDownloader_BAT_Seraph_ABFI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 2b 2e 2b 33 2b 38 16 2d 09 2b 09 2b 0a 6f ?? ?? ?? 0a de 10 08 2b f4 07 2b f3 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 2e 06 2b cf } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {53 00 6d 00 73 00 6e 00 6e 00 7a 00 61 00 70 00 7a 00 62 00 71 00 78 00 71 00 } //1 Smsnnzapzbqxq
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}