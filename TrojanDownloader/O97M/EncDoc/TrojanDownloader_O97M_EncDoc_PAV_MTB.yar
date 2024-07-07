
rule TrojanDownloader_O97M_EncDoc_PAV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 22 73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 64 65 62 75 67 2e 70 72 69 6e 74 6d 73 67 62 6f 78 28 22 65 72 72 6f 72 21 70 6c 65 61 73 65 72 65 2d 69 6e 73 74 61 6c 6c 6f 66 66 69 63 65 22 2c 76 62 6f 6b 63 61 6e 63 65 6c 29 3b 72 65 74 75 72 6e 73 3b 31 64 } //1 1"subauto_open()debug.printmsgbox("error!pleasere-installoffice",vbokcancel);returns;1d
		$a_01_1 = {2e 73 68 65 6c 6c 28 63 35 79 62 77 65 36 79 70 2b 72 65 77 64 68 31 73 38 64 2b 6c 72 70 62 63 6b 6a 70 6f 2b 77 6a 39 77 6f 31 78 6c 78 29 29 65 6e 64 73 } //1 .shell(c5ybwe6yp+rewdh1s8d+lrpbckjpo+wj9wo1xlx))ends
		$a_01_2 = {75 69 68 70 38 29 29 2c 31 29 29 78 6f 72 61 73 63 28 6d 69 64 28 70 77 74 6b 6c 76 6b 75 38 2c 6a 36 39 70 6d 75 61 76 39 2c 31 29 29 29 6e 65 78 74 6a 36 } //1 uihp8)),1))xorasc(mid(pwtklvku8,j69pmuav9,1)))nextj6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}