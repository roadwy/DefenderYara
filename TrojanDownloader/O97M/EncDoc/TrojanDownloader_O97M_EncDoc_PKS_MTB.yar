
rule TrojanDownloader_O97M_EncDoc_PKS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2d 77 20 68 69 20 73 6c 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 5e 72 20 2d 53 6f 75 72 63 65 } //1 -w hi sleep -Se 31;Start-BitsTransfe^r -Source
		$a_01_1 = {68 74 74 60 70 73 3a 2f 2f 6a 6f 6c 64 69 73 68 6f 70 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 67 61 74 61 31 2e 65 60 78 65 } //1 htt`ps://joldishop.com/wp-content/plugins/gata1.e`xe
		$a_01_2 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 67 6f 64 2e 63 6d 22 } //1 = "C:\Users\Public\agod.cm"
		$a_01_3 = {2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 62 6f 72 6e 65 78 69 73 74 2e 65 60 78 65 } //1 -Dest C:\Users\Public\Documents\bornexist.e`xe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}