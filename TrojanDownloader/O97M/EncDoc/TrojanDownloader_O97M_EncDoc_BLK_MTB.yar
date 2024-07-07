
rule TrojanDownloader_O97M_EncDoc_BLK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 6e 65 77 2d 6f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 } //1 (new-object System.Net.WebClient)
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 6f 6e 62 64 65 6d 69 2f 76 61 6a 6e 65 6f 64 7a 39 6d 74 2f 67 68 2d 70 61 67 65 73 2f 31 61 36 7a 74 39 6f 73 79 64 36 77 73 79 2e 6a 70 67 } //1 https://raw.githubusercontent.com/onbdemi/vajneodz9mt/gh-pages/1a6zt9osyd6wsy.jpg
		$a_01_2 = {25 74 6d 70 25 5c 5c 52 59 59 49 49 70 7a 2e 6a 61 72 } //1 %tmp%\\RYYIIpz.jar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}