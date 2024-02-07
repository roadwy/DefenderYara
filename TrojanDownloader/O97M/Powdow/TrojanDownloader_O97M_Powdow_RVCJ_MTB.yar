
rule TrojanDownloader_O97M_Powdow_RVCJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 73 68 65 6c 6c 65 78 65 63 75 74 65 62 6d 76 6b 64 6c 66 64 6a 6b 6c 66 61 73 66 77 2c 70 65 6f 73 6b 61 77 65 66 67 65 61 2c 22 22 2c 22 6f 70 65 6e 22 2c 30 65 6e 64 73 75 62 } //01 00  .shellexecutebmvkdlfdjklfasfw,peoskawefgea,"","open",0endsub
		$a_01_1 = {3d 72 65 70 6c 61 63 65 28 6f 65 69 6f 69 77 61 6f 66 73 6f 64 61 66 2c 70 77 6f 65 6b 64 73 66 77 2c 22 22 29 } //01 00  =replace(oeioiwaofsodaf,pwoekdsfw,"")
		$a_01_2 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 73 65 74 69 65 6f 61 6c 73 64 66 61 73 66 65 66 61 66 61 77 65 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //00 00  document_open()setieoalsdfasfefafawe=createobject("shell.application")
	condition:
		any of ($a_*)
 
}