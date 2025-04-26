
rule TrojanDownloader_O97M_Obfuse_RVBP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 72 65 76 65 72 73 65 64 74 65 78 74 26 6d 69 64 28 74 65 78 74 2c 28 6c 65 6e 67 74 68 2d 7a 29 2c 31 29 6e 65 78 74 } //1 =reversedtext&mid(text,(length-z),1)next
		$a_01_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 6e 74 22 29 } //1 createobject("wscript.shell")specialpath=wshshell.specialfolders("recent")
		$a_03_2 = {2e 6f 70 65 6e 22 67 65 74 22 2c [0-c8] 28 22 [0-64] 22 29 2c 66 61 6c 73 65 } //1
		$a_01_3 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 } //1 =chr(50)+chr(48)+chr(48)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}