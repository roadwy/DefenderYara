
rule TrojanDownloader_O97M_EncDoc_SSMG_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 51 76 53 6d 4c 52 4c 6f 70 50 6c 45 66 55 43 74 4a 67 4f 6a 58 61 48 4d 2e 76 62 73 } //1 C:\ProgramData\QvSmLRLopPlEfUCtJgOjXaHM.vbs
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}