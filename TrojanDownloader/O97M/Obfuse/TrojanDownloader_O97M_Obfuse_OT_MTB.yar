
rule TrojanDownloader_O97M_Obfuse_OT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 68 31 2e 78 73 6c 22 } //1 \h1.xsl"
		$a_01_1 = {5c 68 31 2e 63 6f 6d 22 } //1 \h1.com"
		$a_01_2 = {66 72 6d 2e 74 65 78 74 62 6f 78 32 2e 74 65 78 74 } //1 frm.textbox2.text
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_01_4 = {2e 65 78 65 63 20 61 71 54 66 35 64 } //1 .exec aqTf5d
		$a_01_5 = {28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 67 48 75 38 } //1 ("comments") & agHu8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}