
rule TrojanDownloader_O97M_Obfuse_NYEZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NYEZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e } //1 = CreateObject("wscript.shell").Run
		$a_03_1 = {68 74 74 70 3a 2f 2f 73 63 61 6c 61 64 65 76 65 6c 6f 70 6d 65 6e 74 73 2e 73 63 61 6c 61 64 65 76 63 6f 2e 63 6f 6d 2f 31 37 2f [0-0a] 2e 65 78 } //1
		$a_03_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-14] 2e 65 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}