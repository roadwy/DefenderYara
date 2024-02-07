
rule TrojanDownloader_O97M_EncDoc_QK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 62 69 6e 2e 6e 65 74 2f 65 73 6e 35 67 35 38 34 31 64 64 72 64 30 39 79 2f 62 72 77 66 73 2e 6d 73 69 } //01 00  https://filebin.net/esn5g5841ddrd09y/brwfs.msi
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 64 6f 77 73 49 6e 73 74 61 6c 6c 65 72 2e 49 6e 73 74 61 6c 6c 65 72 22 29 } //00 00  CreateObject("WindowsInstaller.Installer")
	condition:
		any of ($a_*)
 
}