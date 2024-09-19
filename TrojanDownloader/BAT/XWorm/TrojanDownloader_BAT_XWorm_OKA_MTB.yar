
rule TrojanDownloader_BAT_XWorm_OKA_MTB{
	meta:
		description = "TrojanDownloader:BAT/XWorm.OKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6f 62 6a 5c 44 65 62 75 67 5c 42 6f 6f 74 73 74 72 61 70 70 65 72 31 34 38 38 2e 70 64 62 } //1 obj\Debug\Bootstrapper1488.pdb
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 73 37 31 35 73 61 73 2e 73 74 6f 72 61 67 65 2e 79 61 6e 64 65 78 2e 6e 65 74 } //1 https://s715sas.storage.yandex.net
		$a_81_2 = {6c 69 6d 69 74 3d 30 26 63 6f 6e 74 65 6e 74 5f 74 79 70 65 3d 61 70 70 6c 69 63 61 74 69 6f 6e 25 32 46 78 2d 64 6f 73 65 78 65 63 26 6f 77 6e 65 72 5f 75 69 64 3d 31 38 39 31 30 30 32 33 35 35 26 66 73 69 7a 65 3d 36 32 34 36 34 } //1 limit=0&content_type=application%2Fx-dosexec&owner_uid=1891002355&fsize=62464
		$a_81_3 = {4c 6f 61 64 65 72 2e 65 78 65 } //1 Loader.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}