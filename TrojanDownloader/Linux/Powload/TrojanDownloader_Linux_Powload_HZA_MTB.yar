
rule TrojanDownloader_Linux_Powload_HZA_MTB{
	meta:
		description = "TrojanDownloader:Linux/Powload.HZA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {3d 20 73 68 65 6c 6c 6f 62 6a 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 73 74 61 72 74 75 70 22 29 20 26 20 22 5c 22 } //1 = shellobj.specialfolders("startup") & "\"
		$a_01_2 = {3d 20 22 68 74 74 70 73 3a 2f 2f 69 6d 6d 6f 72 74 61 6c 73 68 69 65 6c 64 2e 63 6f 6d 2f 72 65 61 64 2e 70 68 70 22 } //1 = "https://immortalshield.com/read.php"
		$a_01_3 = {20 26 20 22 63 32 62 37 32 66 38 36 62 38 63 61 35 31 36 34 32 63 34 61 39 30 32 38 38 37 38 33 30 64 33 65 2e 6a 73 22 } //1  & "c2b72f86b8ca51642c4a902887830d3e.js"
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 22 29 } //1 = CreateObject("msxml2.xmlhttp")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}