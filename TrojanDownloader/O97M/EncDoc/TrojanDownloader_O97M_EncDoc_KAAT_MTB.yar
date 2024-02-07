
rule TrojanDownloader_O97M_EncDoc_KAAT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KAAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6f 70 65 6e 2e 6a 73 22 } //01 00  = "C:\Users\Public\open.js"
		$a_01_1 = {3d 20 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b 4b 41 4c 59 4a 41 20 3d 20 22 22 6d 73 68 74 61 20 } //01 00  = new ActiveXObject('Wscript.Shell');KALYJA = ""mshta 
		$a_01_2 = {3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f 73 6e 69 70 70 65 74 73 2f 72 69 6b 69 6d 61 72 74 69 6e 70 6c 61 63 65 2f 36 45 45 65 4d 34 2f 38 33 62 66 66 35 37 30 39 39 31 39 65 33 38 65 66 31 63 33 62 62 63 63 65 39 37 35 38 63 31 61 62 36 31 34 30 36 62 33 2f 66 69 6c 65 73 2f 64 69 76 69 6e 65 66 69 6e 61 6c } //01 00  ://bitbucket.org/!api/2.0/snippets/rikimartinplace/6EEeM4/83bff5709919e38ef1c3bbcce9758c1ab61406b3/files/divinefinal
		$a_01_3 = {3d 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 2b 20 6f 70 65 6e 74 65 78 74 } //01 00  = "explorer.exe " + opentext
		$a_01_4 = {44 65 62 75 67 2e 50 72 69 6e 74 } //01 00  Debug.Print
		$a_01_5 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 25 28 74 65 78 74 66 69 6c 65 31 29 } //00 00  Call VBA.Shell%(textfile1)
	condition:
		any of ($a_*)
 
}