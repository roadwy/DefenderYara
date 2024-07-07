
rule TrojanDownloader_O97M_Bumblebee_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Bumblebee.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 73 68 65 6c 6c 22 62 31 30 3d 62 31 30 26 22 2e 72 75 6e 22 22 22 } //1 objshell"b10=b10&".run"""
		$a_01_1 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 70 61 6e 64 65 6e 76 69 72 6f 6e 6d 65 6e 74 73 74 72 69 6e 67 73 28 22 25 74 65 6d 70 25 22 29 74 65 6d 70 66 69 6c 65 6e 61 6d 65 } //1 =createobject("wscript.shell").expandenvironmentstrings("%temp%")tempfilename
		$a_01_2 = {2e 63 75 73 74 6f 6d 64 6f 63 75 6d 65 6e 74 70 72 6f 70 65 72 74 69 65 73 28 22 73 70 65 63 69 61 6c 70 72 6f 70 73 33 22 29 2e 76 61 6c 75 65 74 73 2e 77 72 69 74 65 6c 69 6e 65 62 34 74 73 2e 77 72 69 74 65 6c 69 6e 65 62 31 30 26 62 31 26 22 22 22 22 22 22 26 62 32 26 22 22 22 22 22 22 22 2c 30 2c 2d 31 22 } //1 .customdocumentproperties("specialprops3").valuets.writelineb4ts.writelineb10&b1&""""""&b2&""""""",0,-1"
		$a_01_3 = {73 75 62 64 6f 63 75 6d 65 6e 74 5f 63 6c 6f 73 65 28 29 6d 6f 64 75 6c 65 31 2e 63 68 65 63 6b 65 72 65 6e 64 73 75 62 } //1 subdocument_close()module1.checkerendsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}