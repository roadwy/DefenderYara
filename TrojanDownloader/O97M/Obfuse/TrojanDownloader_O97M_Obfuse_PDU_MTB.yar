
rule TrojanDownloader_O97M_Obfuse_PDU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 64 69 6d 77 73 68 73 68 65 6c 6c 61 73 6f 62 6a 65 63 74 } //1 =chr(50)+chr(48)+chr(48)dimwshshellasobject
		$a_01_1 = {73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 6e 65 74 68 6f 6f 64 22 29 64 69 6d 68 } //1 specialpath=wshshell.specialfolders("nethood")dimh
		$a_01_2 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 62 66 6e 66 68 74 79 6f 6f 75 6e 28 22 69 65 78 5f 6f 5d 77 63 5d 78 3b 6e 6e 22 29 76 62 6e 64 2e 6f 70 65 6e 22 67 65 74 22 2c 62 66 6e 66 68 74 79 6f 6f 75 6e } //1 =specialpath+bfnfhtyooun("iex_o]wc]x;nn")vbnd.open"get",bfnfhtyooun
		$a_01_3 = {3d 31 74 6f 6c 65 6e 28 66 69 6b 6d 67 62 29 6b 6d 69 6f 6c 3d 6b 6d 69 6f 6c 26 63 68 72 28 61 73 63 28 6d 69 64 28 66 69 6b 6d 67 62 2c 68 64 6e 72 79 2c 31 29 29 2d 31 33 29 6e 65 78 74 } //1 =1tolen(fikmgb)kmiol=kmiol&chr(asc(mid(fikmgb,hdnry,1))-13)next
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}