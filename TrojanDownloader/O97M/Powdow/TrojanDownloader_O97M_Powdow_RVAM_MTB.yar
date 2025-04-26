
rule TrojanDownloader_O97M_Powdow_RVAM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 31 38 32 45 51 4d 70 69 } //1 ://pastebin.com/raw/182EQMpi
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 22 62 46 76 42 79 2e 76 62 73 22 } //1 CreateObject("WScript.Shell").Run "bFvBy.vbs"
		$a_01_2 = {46 74 51 44 61 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 4b 5a 58 6e 52 2c 20 46 61 6c 73 65 } //1 FtQDa.Open "GET", KZXnR, False
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}