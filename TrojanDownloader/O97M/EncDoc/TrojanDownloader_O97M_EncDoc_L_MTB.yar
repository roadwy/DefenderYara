
rule TrojanDownloader_O97M_EncDoc_L_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.L!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 64 69 76 69 6e 65 6c 65 76 65 72 61 67 65 2e 6f 72 67 2f 64 65 2e 70 68 70 3f 64 65 3d 32 49 4e 46 4f } //1 https://divineleverage.org/de.php?de=2INFO
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 2e 72 65 67 } //1 C:\ProgramData\1.reg
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}