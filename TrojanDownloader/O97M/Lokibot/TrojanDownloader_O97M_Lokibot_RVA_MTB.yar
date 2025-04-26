
rule TrojanDownloader_O97M_Lokibot_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Lokibot.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 6f 6e 65 72 72 6f 72 67 6f 74 6f 65 72 72 6f 72 68 61 6e 64 6c 65 72 63 6f 6e 73 74 64 6f 77 6e 6c 6f 61 64 5f 75 72 6c 61 73 73 74 72 69 6e 67 3d 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 32 36 35 35 39 32 36 38 30 37 30 30 37 31 31 30 30 36 2f 31 32 36 35 38 32 33 39 31 37 31 30 31 30 32 33 32 35 32 2f [0-0f] 2e 65 78 65 3f 65 78 3d } //1
		$a_01_1 = {3d 65 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 26 22 5c 64 6f 77 6e 6c 6f 61 64 65 64 5f 66 69 6c 65 2e 65 78 65 22 } //1 =environ$("tmp")&"\downloaded_file.exe"
		$a_01_2 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 22 29 78 6d 6c 68 74 74 70 2e 6f 70 65 6e 22 67 65 74 22 2c 75 72 6c 2c 66 61 6c 73 65 78 6d 6c 68 74 74 70 2e 73 65 6e 64 } //1 =createobject("msxml2.xmlhttp")xmlhttp.open"get",url,falsexmlhttp.send
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}