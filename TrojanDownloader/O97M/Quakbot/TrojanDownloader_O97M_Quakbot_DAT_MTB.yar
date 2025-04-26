
rule TrojanDownloader_O97M_Quakbot_DAT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Quakbot.DAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 61 72 6f 73 61 6e 2e 69 72 2f 78 75 6a 70 75 6f 6d 6b 61 6b 61 } //1 http://garosan.ir/xujpuomkaka
		$a_01_1 = {68 74 74 70 3a 2f 2f 67 61 72 6f 73 61 6e 2e 69 72 2f 78 75 6a 70 75 6f 6d 6b 61 6b 61 2f 35 33 30 33 34 30 2e 70 6e 67 } //1 http://garosan.ir/xujpuomkaka/530340.png
		$a_01_2 = {43 3a 5c 44 61 74 6f 70 5c } //1 C:\Datop\
		$a_01_3 = {7a 69 70 66 6c 64 72 } //1 zipfldr
		$a_01_4 = {4a 4a 43 43 43 4a } //1 JJCCCJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}