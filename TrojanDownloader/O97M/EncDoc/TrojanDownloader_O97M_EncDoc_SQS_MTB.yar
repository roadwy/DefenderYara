
rule TrojanDownloader_O97M_EncDoc_SQS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SQS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 2e } //1 = Replace("cmd.
		$a_03_1 = {3a 2f 2f 64 64 6c 38 2e 64 61 74 61 2e 68 75 2f 90 02 ff 2f 90 02 0a 2f 90 02 0a 2f 90 00 } //1
		$a_01_2 = {2e 53 61 76 65 } //1 .Save
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 22 72 75 6e 64 4b 66 61 75 38 73 38 61 64 36 79 61 4b 66 61 75 38 73 38 61 64 36 79 61 33 32 20 75 72 4b 66 61 75 38 73 38 61 64 36 79 61 2e 64 4b 66 61 75 38 73 38 61 64 36 79 61 4b 66 61 75 38 73 38 61 64 36 79 61 2c 4f 70 65 6e 55 52 4c } //1 = Replace("rundKfau8s8ad6yaKfau8s8ad6ya32 urKfau8s8ad6ya.dKfau8s8ad6yaKfau8s8ad6ya,OpenURL
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_SQS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SQS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6f 70 65 6e 2e 6a 73 22 } //1 = "C:\Users\Public\open.js"
		$a_01_1 = {3d 20 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b 4b 41 4c 59 4a 41 20 3d 20 22 22 6d 73 68 74 61 } //1 = new ActiveXObject('Wscript.Shell');KALYJA = ""mshta
		$a_01_2 = {3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f 73 6e 69 70 70 65 74 73 2f 72 69 6b 69 6d 61 72 74 69 6e 70 6c 61 63 65 2f 39 45 45 41 39 62 2f 31 61 36 32 30 35 66 66 65 61 64 32 37 31 36 34 32 39 36 38 33 34 66 33 62 64 31 30 33 65 66 64 64 30 66 65 34 37 66 34 2f 66 69 6c 65 73 2f 6d 61 6e 61 76 69 73 69 6f 6e 66 69 6e 61 6c } //1 ://bitbucket.org/!api/2.0/snippets/rikimartinplace/9EEA9b/1a6205ffead27164296834f3bd103efdd0fe47f4/files/manavisionfinal
		$a_01_3 = {3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f 73 6e 69 70 70 65 74 73 2f 72 69 6b 69 6d 61 72 74 69 6e 70 6c 61 63 65 2f 4b 4d 4d 65 36 70 2f 38 34 64 64 38 39 65 33 64 61 30 61 35 39 37 66 31 37 38 61 66 38 34 62 37 35 66 61 33 30 31 38 36 39 62 62 39 37 34 30 2f 66 69 6c 65 73 2f 63 68 61 72 6c 65 73 66 69 6e 61 6c } //1 ://bitbucket.org/!api/2.0/snippets/rikimartinplace/KMMe6p/84dd89e3da0a597f178af84b75fa301869bb9740/files/charlesfinal
		$a_01_4 = {3d 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 } //1 = "explorer.exe "
		$a_01_5 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_6 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 25 28 74 65 78 74 66 69 6c 65 31 29 } //1 Call VBA.Shell%(textfile1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}