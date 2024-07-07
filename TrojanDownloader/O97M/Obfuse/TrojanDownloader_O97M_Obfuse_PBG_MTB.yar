
rule TrojanDownloader_O97M_Obfuse_PBG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 6c 69 63 5c 34 35 36 74 72 79 74 67 72 65 33 65 34 35 79 72 74 68 74 67 72 2e 65 78 65 } //1 & "lic\456trytgre3e45yrthtgr.exe
		$a_03_1 = {52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 61 61 64 72 6e 67 6d 36 72 73 68 61 61 64 72 6e 67 6d 36 6c 6c 2f 57 20 30 31 20 63 75 90 02 04 72 6c 20 68 74 74 90 02 01 70 3a 2f 2f 39 31 2e 31 30 37 2e 32 31 30 2e 32 30 37 2f 74 69 6e 79 74 61 73 6b 2e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}