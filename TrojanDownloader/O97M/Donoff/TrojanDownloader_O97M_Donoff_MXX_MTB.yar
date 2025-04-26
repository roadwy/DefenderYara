
rule TrojanDownloader_O97M_Donoff_MXX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //2 CreateObject("Microsoft.XMLHTTP")
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //2 CreateObject("ADODB.Stream")
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //2 CreateObject("WScript.Shell")
		$a_01_3 = {73 68 65 6c 6c 5f 6f 62 6a 2e 65 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 41 50 50 44 41 54 41 25 22 29 } //2 shell_obj.expandEnvironmentStrings("%APPDATA%")
		$a_01_4 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 39 35 2e 31 38 31 2e 31 36 34 2e 34 33 2f 6a 6f 70 61 2e 65 78 65 22 } //2 URL = "http://95.181.164.43/jopa.exe"
		$a_01_5 = {68 74 74 70 5f 6f 62 6a 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 55 52 4c 2c 20 46 61 6c 73 65 } //2 http_obj.Open "GET", URL, False
		$a_01_6 = {52 55 4e 43 4d 44 20 3d 20 41 50 50 50 41 54 48 20 2b 20 22 6a 6f 70 61 2e 65 78 65 22 } //2 RUNCMD = APPPATH + "jopa.exe"
		$a_01_7 = {73 68 65 6c 6c 5f 6f 62 6a 2e 52 75 6e 20 52 55 4e 43 4d 44 } //2 shell_obj.Run RUNCMD
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=16
 
}