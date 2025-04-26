
rule TrojanDownloader_Win32_Banload_AXR{
	meta:
		description = "TrojanDownloader:Win32/Banload.AXR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 39 38 2e 32 33 2e 32 35 30 2e 32 31 31 2f 31 39 30 38 2f } //1 http://198.23.250.211/1908/
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 39 32 2e 32 31 30 2e 31 39 35 2e 35 30 2f 31 30 30 39 2f } //1 http://192.210.195.50/1009/
		$a_01_2 = {3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 6b 20 72 65 67 73 76 72 33 32 2e 65 78 65 20 20 22 } //1 :\Windows\System32\cmd.exe /k regsvr32.exe  "
		$a_01_3 = {00 69 64 2e 73 79 73 00 } //1
		$a_03_4 = {32 2e 6a 70 67 22 [0-20] 36 2e 6a 70 67 22 [0-20] 35 2e 6a 70 67 22 } //1
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //1 SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}