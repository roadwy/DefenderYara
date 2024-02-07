
rule TrojanDownloader_O97M_Lokibot_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Lokibot.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 37 38 30 32 32 33 31 35 38 38 33 32 39 38 38 32 30 31 2f 37 38 30 33 38 30 37 35 38 38 36 32 30 36 39 37 36 30 2f 52 4a 57 56 2e 65 78 65 } //02 00  https://cdn.discordapp.com/attachments/780223158832988201/780380758862069760/RJWV.exe
		$a_00_1 = {68 74 74 70 3a 2f 2f 70 69 72 61 74 65 73 6d 6f 6b 65 72 2e 63 6f 6d 2f 4f 52 44 45 52 25 32 30 46 4f 52 4d 25 32 30 44 45 4e 4b 2f 4f 52 44 45 52 25 32 30 46 4f 52 4d 25 32 30 44 45 4e 4b 2e 65 78 65 } //02 00  http://piratesmoker.com/ORDER%20FORM%20DENK/ORDER%20FORM%20DENK.exe
		$a_00_2 = {45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 2b 22 61 70 67 68 73 6f 62 69 65 76 6c 61 71 73 6b 6b 66 79 76 61 76 76 6a 77 65 62 77 65 68 66 76 69 6e 75 71 61 64 77 6d 78 76 77 76 6c 77 2e 65 78 65 22 2c 30 2c 30 } //02 00  Environ("APPDATA") +"apghsobievlaqskkfyvavvjwebwehfvinuqadwmxvwvlw.exe",0,0
		$a_00_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c 22 20 2b 22 66 62 79 72 68 69 74 65 70 67 7a 71 7a 74 6e 71 70 78 76 73 6e 7a 71 6b 76 6e 67 67 6e 6c 69 61 64 6f 63 6a 76 63 65 6e 78 6c 73 66 6b 2e 65 78 65 22 2c 30 2c 30 } //01 00  C:\Users\Public\Downloads\" +"fbyrhitepgzqztnqpxvsnzqkvnggnliadocjvcenxlsfk.exe",0,0
		$a_02_4 = {53 68 65 6c 6c 28 90 02 32 2c 20 76 62 4e 6f 72 6d 61 6c 4e 6f 46 6f 63 75 73 29 90 00 } //01 00 
		$a_00_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_6 = {75 72 6c 6d 6f 6e } //00 00  urlmon
	condition:
		any of ($a_*)
 
}