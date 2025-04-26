
rule TrojanDownloader_O97M_XenoRAT_QBAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/XenoRAT.QBAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 64 69 6d 77 73 68 73 68 65 6c 6c 61 73 6f 62 6a 65 63 74 64 69 6d 7a 74 69 68 73 70 65 63 69 61 6c 70 61 74 68 6a 69 6e 61 61 73 73 74 72 69 6e 67 64 69 6d 61 73 69 6e 74 65 67 65 72 3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 } //1 subworkbook_open()dimwshshellasobjectdimztihspecialpathjinaasstringdimasinteger=chr(50)+chr(48)+chr(48)
		$a_01_1 = {73 65 74 77 73 68 73 68 65 6c 6c 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 setwshshell=createobject("wscript.shell")
		$a_01_2 = {7a 74 69 68 73 70 65 63 69 61 6c 70 61 74 68 6a 69 6e 61 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 6e 74 22 29 } //1 ztihspecialpathjina=wshshell.specialfolders("recent")
		$a_01_3 = {73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 } //1 set=createobject("microsoft.xmlhttp")
		$a_01_4 = {73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 set=createobject("shell.application")
		$a_01_5 = {3d 7a 74 69 68 73 70 65 63 69 61 6c 70 61 74 68 6a 69 6e 61 2b 28 22 5c 6d 6a 71 6e 7a 76 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 77 77 77 2e 62 67 6c 76 2e 2f 64 62 2d 2f 76 67 2f 6a 2e 22 29 } //1 =ztihspecialpathjina+("\mjqnzv.").open"get",("h://www.bglv./db-/vg/j.")
		$a_01_6 = {73 74 61 74 75 73 3d 32 30 30 74 68 65 6e 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 2e 6f 70 65 6e 2e 74 79 70 65 3d 2e 77 72 69 74 65 2e 73 61 76 65 74 6f 66 69 6c 65 } //1 status=200thenset=createobject("adodb.stream").open.type=.write.savetofile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}