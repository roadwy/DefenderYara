
rule TrojanDownloader_O97M_Obfuse_RPI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RPI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 69 31 74 6f 6c 65 6e 78 64 65 63 72 79 70 74 65 64 64 65 63 72 79 70 74 65 64 63 68 72 61 73 63 6d 69 64 78 69 31 78 6f 72 6b 65 79 6e 65 78 74 69 } //1 fori1tolenxdecrypteddecryptedchrascmidxi1xorkeynexti
		$a_01_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 77 73 63 72 69 70 74 73 68 65 6c 6c 72 75 6e 64 65 63 72 79 70 74 65 64 30 65 6e 64 73 75 62 } //1 createobjectwscriptshellrundecrypted0endsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_RPI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RPI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 64 6f 77 6e 6c 6f 61 64 2f 6b 6f 6b 65 61 71 33 69 2f 77 5f 76 6e 74 70 63 77 2e 33 34 31 66 39 37 63 35 64 37 31 37 37 30 65 37 37 30 61 31 30 34 33 62 36 34 65 63 39 31 39 63 22 72 65 6e 61 6e 63 64 74 3d 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 30 2c 69 6d 61 67 65 6d 73 69 6d 70 6c 65 73 63 64 74 2c 72 65 6e 61 6e 63 64 74 26 22 64 6f 63 75 6d 65 6e 74 2e 65 78 65 22 } //1 ="https://www.4sync.com/web/directdownload/kokeaq3i/w_vntpcw.341f97c5d71770e770a1043b64ec919c"renancdt="c:\users\public\"urldownloadtofile0,imagemsimplescdt,renancdt&"document.exe"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}