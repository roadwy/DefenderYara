
rule TrojanDownloader_O97M_Emotet_DD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.DD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 2e 6f 6f 63 63 78 78 } //1 1.ooccxx
		$a_01_1 = {32 2e 6f 6f 63 63 78 78 } //1 2.ooccxx
		$a_01_2 = {33 2e 6f 6f 63 63 78 78 } //1 3.ooccxx
		$a_01_3 = {34 2e 6f 6f 63 63 78 78 } //1 4.ooccxx
		$a_03_4 = {75 72 6c 6d 6f 6e 90 02 03 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}