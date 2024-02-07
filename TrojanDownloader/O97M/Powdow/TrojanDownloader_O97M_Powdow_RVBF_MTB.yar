
rule TrojanDownloader_O97M_Powdow_RVBF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {2f 2f 77 77 77 2e 61 73 69 61 6e 65 78 70 6f 72 74 67 6c 61 73 73 2e 73 68 6f 70 2f 70 2f 90 02 04 2e 68 74 6d 6c 90 00 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 5e 28 22 77 73 63 72 69 70 74 20 22 20 2b 20 6b 6f 61 6b 73 6f 64 6b 61 73 64 29 0d 0a 45 6e 64 20 53 75 62 } //01 00  慃汬匠敨汬⡞眢捳楲瑰∠⬠欠慯獫摯慫摳ഩ䔊摮匠扵
		$a_01_2 = {41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b 4b 41 4c 59 4a 41 20 3d 20 22 22 6d 73 68 74 22 } //01 00  ActiveXObject('Wscript.Shell');KALYJA = ""msht"
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 7a 61 69 6d 2e 6a 73 } //01 00  C:\Users\Public\zaim.js
		$a_01_4 = {4f 70 65 6e 20 6b 6f 61 6b 73 6f 64 6b 61 73 64 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 33 32 31 } //00 00  Open koaksodkasd For Output As #321
	condition:
		any of ($a_*)
 
}