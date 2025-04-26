
rule TrojanDownloader_Win32_Banload_OW{
	meta:
		description = "TrojanDownloader:Win32/Banload.OW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 32 e8 ?? ?? ?? ff 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ff 43 4e 75 dc } //3
		$a_01_1 = {6f 20 61 72 71 75 69 76 6f } //1 o arquivo
		$a_01_2 = {4d 73 6e 48 6f 74 } //1 MsnHot
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}