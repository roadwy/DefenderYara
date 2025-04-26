
rule TrojanDownloader_O97M_Powdow_RR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 65 6e 76 69 72 6f 6e 24 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 26 } //1 =environ$("userprofile")&
		$a_01_1 = {2e 73 65 6e 64 3d 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 69 66 2e 73 74 61 74 75 73 3d 32 30 30 74 68 65 6e 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 2e 6f 70 65 6e 2e 74 79 70 65 3d 2e 77 72 69 74 65 2e 73 61 76 65 74 6f 66 69 6c 65 } //1 .send=.responsebodyif.status=200thenset=createobject("adodb.stream").open.type=.write.savetofile
		$a_01_2 = {28 22 68 3a 2f 2f 77 77 77 2e 6a } //1 ("h://www.j
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}