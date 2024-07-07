
rule TrojanDownloader_O97M_Obfuse_KDKD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KDKD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 79 73 66 68 6d 2e 6f 70 65 6e 28 72 64 68 74 6a 2b 22 5c 73 66 6f 77 71 2e 6a 73 22 29 } //1 aysfhm.open(rdhtj+"\sfowq.js")
		$a_01_1 = {61 63 74 69 76 65 73 68 65 65 74 2e 6f 6c 65 6f 62 6a 65 63 74 73 28 31 29 2e 63 6f 70 79 } //1 activesheet.oleobjects(1).copy
		$a_01_2 = {61 79 73 66 68 6d 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 6d 65 72 6d 6b 64 28 29 29 } //1 aysfhm=createobject(mermkd())
		$a_01_3 = {77 6f 72 6b 62 6f 6f 6b 5f 61 63 74 69 76 61 74 65 28 29 63 61 6c 6c 66 73 70 61 65 6e 64 73 75 62 73 75 62 73 72 68 7a 66 6c 78 66 63 28 72 64 68 74 6a 29 } //1 workbook_activate()callfspaendsubsubsrhzflxfc(rdhtj)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}