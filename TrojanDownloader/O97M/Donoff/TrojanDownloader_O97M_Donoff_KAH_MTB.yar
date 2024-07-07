
rule TrojanDownloader_O97M_Donoff_KAH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.KAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 72 68 62 2d 69 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 2e 63 6f 6d 2f 70 72 6f 6a 65 63 74 73 2f 65 6e 71 75 69 72 79 2e 7a 69 70 22 } //1 ://www.rhb-international.com/projects/enquiry.zip"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 4d 79 44 6f 63 75 6d 65 6e 74 73 22 29 20 26 20 22 5c 65 6e 71 75 69 72 79 2e 7a 69 70 22 } //1 = CreateObject("WScript.Shell").SpecialFolders("MyDocuments") & "\enquiry.zip"
		$a_01_2 = {3d 20 70 61 74 68 6e 61 6d 65 20 26 20 22 5c 22 20 26 20 22 65 6e 71 75 69 72 79 2e 7a 69 70 22 } //1 = pathname & "\" & "enquiry.zip"
		$a_01_3 = {27 53 68 65 6c 6c 20 22 52 75 6e 44 4c 4c 33 32 2e 65 78 65 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 53 68 69 6d 67 76 77 2e 64 6c 6c 2c 49 6d 61 67 65 56 69 65 77 5f 46 75 6c 6c 73 63 72 65 65 6e 20 22 20 26 20 70 61 74 68 6e 61 6d 65 } //1 'Shell "RunDLL32.exe C:\Windows\System32\Shimgvw.dll,ImageView_Fullscreen " & pathname
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}