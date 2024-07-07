
rule TrojanDownloader_O97M_Netwire_YB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Netwire.YB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 75 74 46 69 6c 65 20 28 27 74 65 73 74 35 27 2b 27 2e 65 78 65 27 29 3b 20 26 28 27 2e 2f 74 65 73 74 35 27 2b 27 2e 65 27 2b 27 78 27 2b 27 65 27 29 42 } //1 OutFile ('test5'+'.exe'); &('./test5'+'.e'+'x'+'e')B
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 20 68 20 49 60 77 52 } //1 powershell.exe -w h I`wR
		$a_01_2 = {28 27 68 74 27 2b 27 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 79 63 6c 76 75 6a 75 27 29 } //1 ('ht'+'tps://tinyurl.com/yyclvuju')
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}