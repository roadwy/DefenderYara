
rule TrojanDownloader_O97M_Endeeto_A{
	meta:
		description = "TrojanDownloader:O97M/Endeeto.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 22 29 } //1 = CreateObject("MSXML2.XMLHTTP")
		$a_01_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c } //1 .Open "GET",
		$a_01_2 = {2e 53 65 6e 64 20 22 31 32 33 64 74 22 } //1 .Send "123dt"
		$a_01_3 = {2e 72 65 61 64 79 53 74 61 74 65 20 3c 3e 20 34 0d 0a 20 20 20 20 44 6f 45 76 65 6e 74 73 0d 0a 20 20 20 20 4c 6f 6f 70 } //1
		$a_01_4 = {47 6c 72 65 67 20 3d 20 45 6e 76 69 72 6f 6e 28 22 57 49 4e 44 49 52 22 29 } //1 Glreg = Environ("WINDIR")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}