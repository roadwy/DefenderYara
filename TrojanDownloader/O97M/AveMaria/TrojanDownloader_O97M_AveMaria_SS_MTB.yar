
rule TrojanDownloader_O97M_AveMaria_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/AveMaria.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 63 65 72 43 61 6c 6c 2e 4f 6c 6c 65 79 20 3d 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 22 0d 0a 41 63 65 72 43 61 6c 6c 2e 4f 62 6a 65 63 74 49 6e 73 74 61 6e 74 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 68 6a 64 6b 71 6f 77 64 68 71 6f 77 64 68 } //1
		$a_01_1 = {4e 65 77 43 61 6c 6c 73 2e 53 71 6c 53 75 73 73 79 43 61 6c 6c 20 28 41 63 65 72 43 61 6c 6c 2e 4a 6f 6e 61 73 20 2b 20 41 63 65 72 43 61 6c 6c 2e 4d 61 72 74 68 61 20 2b 20 41 63 65 72 43 61 6c 6c 2e 4e 6f 61 68 20 2b 20 41 63 65 72 43 61 6c 6c 2e 41 64 61 6d 29 } //1 NewCalls.SqlSussyCall (AcerCall.Jonas + AcerCall.Martha + AcerCall.Noah + AcerCall.Adam)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}