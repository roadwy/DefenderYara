
rule TrojanDownloader_O97M_Amphitryon_SWA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Amphitryon.SWA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 50 61 74 68 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 4e 41 4d 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 73 74 61 72 74 75 70 2e 62 61 74 22 } //2 filePath = "C:\Users\" & Environ("USERNAME") & "\AppData\Roaming\startup.bat"
		$a_01_1 = {6e 65 74 77 6f 72 6b 69 6e 67 2e 73 33 2e 69 72 2d 74 68 72 2d 61 74 31 2e 61 72 76 61 6e 73 74 6f 72 61 67 65 2e 69 72 2f 50 61 79 6c 6f 61 64 2e 62 61 74 } //2 networking.s3.ir-thr-at1.arvanstorage.ir/Payload.bat
		$a_01_2 = {25 61 70 70 64 61 74 61 25 5c 50 61 79 6c 6f 61 64 2e 62 61 74 } //1 %appdata%\Payload.bat
		$a_01_3 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 73 74 61 72 74 75 70 2e 76 62 73 } //1 \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\startup.vbs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}