
rule Trojan_BAT_Downloader_CF_MTB{
	meta:
		description = "Trojan:BAT/Downloader.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 69 6d 67 75 72 2e 63 6f 6d 2f 61 70 69 2f 75 70 6c 6f 61 64 2e 78 6d 6c } //1 http://imgur.com/api/upload.xml
		$a_81_1 = {66 62 33 31 36 37 37 37 31 35 34 64 34 61 38 31 66 65 31 36 30 36 34 66 64 37 33 63 65 32 36 34 } //1 fb316777154d4a81fe16064fd73ce264
		$a_81_2 = {43 6f 70 79 20 65 78 74 65 72 6e 61 6c 20 55 52 4c 28 73 29 } //1 Copy external URL(s)
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 43 6c 69 65 6e 74 5c 54 65 6d 70 5c 4b 79 71 68 65 42 4c 65 6d 65 5c 73 72 63 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 55 54 46 38 44 65 63 6f 64 2e 70 64 62 } //1 C:\Users\Administrator\Desktop\Client\Temp\KyqheBLeme\src\obj\x86\Debug\UTF8Decod.pdb
		$a_81_4 = {52 65 6e 61 6d 69 6e 67 20 42 79 20 48 61 73 68 } //1 Renaming By Hash
		$a_01_5 = {6d 61 69 6e 4c 69 73 74 5f 4d 6f 75 73 65 44 6f 77 6e } //1 mainList_MouseDown
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_7 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}