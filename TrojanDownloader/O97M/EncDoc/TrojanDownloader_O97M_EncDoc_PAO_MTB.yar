
rule TrojanDownloader_O97M_EncDoc_PAO_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 28 29 72 65 66 6c 65 63 74 6e 65 77 73 3d 22 70 6f 77 65 5e 72 73 22 6c 69 6e 65 63 68 61 6e 67 65 3d } //01 00  open()reflectnews="powe^rs"linechange=
		$a_01_1 = {63 69 74 69 7a 65 6e 67 65 6e 65 72 61 6c 2e 63 22 26 63 68 72 28 31 30 39 29 26 22 64 22 65 6c 73 65 68 65 61 72 74 3d 22 68 5e 65 6c 6c 22 6f 72 64 65 63 69 64 65 } //01 00  citizengeneral.c"&chr(109)&"d"elseheart="h^ell"ordecide
		$a_01_2 = {6f 6e 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 64 6f 63 75 6d 65 6e 74 73 5c 66 6f 72 77 61 72 64 6f 72 2e 65 60 78 65 22 26 22 3b 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 64 6f 63 75 6d 65 6e 74 73 5c 66 6f 72 77 61 72 64 6f 72 2e 65 } //01 00  onc:\users\public\documents\forwardor.e`xe"&";c:\users\public\documents\forwardor.e
		$a_01_3 = {28 73 68 65 65 65 26 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 6f 70 65 6e 28 6c 69 6e 65 63 68 61 6e 67 65 } //00 00  (sheee&"l.application").open(linechange
	condition:
		any of ($a_*)
 
}