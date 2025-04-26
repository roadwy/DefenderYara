
rule TrojanDownloader_O97M_Adnel_L{
	meta:
		description = "TrojanDownloader:O97M/Adnel.L,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3d 20 43 68 72 28 41 73 63 28 49 58 4d 4c 44 4f 4d 45 6c 65 6d 65 6e 74 37 29 20 2d 20 32 33 29 } //1 = Chr(Asc(IXMLDOMElement7) - 23)
		$a_00_1 = {3d 20 43 68 72 28 41 73 63 28 49 58 4d 4c 44 4f 4d 45 6c 65 6d 65 6e 74 37 29 20 2b 20 34 36 29 } //1 = Chr(Asc(IXMLDOMElement7) + 46)
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 49 58 4d 4c 44 4f 4d 45 6c 65 6d 65 6e 74 37 20 3d 20 22 45 } //1 Public Const IXMLDOMElement7 = "E
		$a_00_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 49 58 4d 4c 44 4f 4d 45 6c 65 6d 65 6e 74 38 20 3d 20 22 6d } //1 Public Const IXMLDOMElement8 = "m
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}