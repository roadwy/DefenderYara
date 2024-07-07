
rule TrojanDownloader_O97M_Powdow_PK_MSR{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 20 53 74 72 52 65 76 65 72 73 65 28 22 90 02 1e 26 20 22 2e 22 20 26 20 22 6a 5c 5c 3a 73 22 20 26 20 22 70 74 74 68 22 90 02 0f 61 22 20 26 20 22 74 22 20 26 20 22 68 22 20 26 20 22 73 22 20 26 20 22 6d 22 20 26 20 22 22 22 22 29 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}