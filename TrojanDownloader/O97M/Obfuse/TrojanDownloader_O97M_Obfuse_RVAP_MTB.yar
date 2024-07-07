
rule TrojanDownloader_O97M_Obfuse_RVAP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 73 70 65 65 64 74 65 73 74 2e 74 65 6c 65 32 2e 6e 65 74 2f 31 30 4d 42 2e 7a 69 70 22 2c 20 46 61 6c 73 65 } //5 xHttp.Open "GET", "http://speedtest.tele2.net/10MB.zip", False
		$a_01_1 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 6c 69 73 74 32 34 2e 6f 6e 6c 69 6e 65 2f 6d 73 70 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //5 xHttp.Open "GET", "https://list24.online/msp.exe", False
		$a_01_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 31 30 4d 42 2e 7a 69 70 22 2c 20 32 } //2 .savetofile "10MB.zip", 2
		$a_01_3 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 6d 73 70 2e 65 78 65 22 2c 20 32 } //2 .savetofile "C:\Windows\Temp\msp.exe", 2
		$a_01_4 = {78 48 74 74 70 3a 20 53 65 74 20 78 48 74 74 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=8
 
}