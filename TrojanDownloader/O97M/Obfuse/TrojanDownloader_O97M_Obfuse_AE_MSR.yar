
rule TrojanDownloader_O97M_Obfuse_AE_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AE!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {59 6f 75 20 61 72 65 20 68 61 63 6b 65 64 22 2c 20 [0-10] 2c 20 22 59 6f 75 20 61 72 65 20 68 61 63 6b 65 64 } //1
		$a_02_1 = {53 68 65 6c 6c 20 22 43 3a 5c 77 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 61 6c 63 2e 65 78 65 [0-06] 76 62 4d 61 78 69 6d 69 7a 65 64 46 6f 63 75 73 } //1
		$a_00_2 = {53 65 74 20 49 45 61 70 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 20 27 53 65 74 20 49 45 61 70 70 20 3d 20 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 } //1 Set IEapp = CreateObject("InternetExplorer.Application") 'Set IEapp = InternetExplorer
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}