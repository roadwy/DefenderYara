
rule TrojanDownloader_O97M_EncDoc_BSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 6f 73 6c 6f 62 69 6b 65 72 65 6e 74 61 6c 2e 6e 6f 2e 77 77 31 38 2e 6f 6e 6c 69 6e 65 34 75 2e 6e 6f 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 32 2f 75 70 73 2f 49 4d 47 30 30 31 32 30 34 37 34 2e 65 78 65 } //1 //oslobikerental.no.ww18.online4u.no/wp-includes/ID2/ups/IMG00120474.exe
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_BSM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f 62 39 38 37 66 31 69 33 63 73 73 30 6c 68 6c 2f 34 2e 74 78 74 2f 66 69 6c 65 20 2d 55 73 65 42 20 2d 55 73 65 44 65 66 61 75 6c 74 43 72 65 64 65 6e 74 69 61 6c 73 20 7c 20 26 28 27 4d 4d 4d 27 2e 72 65 70 6c 61 63 65 28 27 4d 4d 4d 27 2c 27 49 27 29 2b 27 64 69 6c 64 6f 27 2e 72 65 70 6c 61 63 65 28 27 64 69 6c 64 6f 27 2c 27 45 58 27 29 29 22 } //1 mediafire.com/file/b987f1i3css0lhl/4.txt/file -UseB -UseDefaultCredentials | &('MMM'.replace('MMM','I')+'dildo'.replace('dildo','EX'))"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}