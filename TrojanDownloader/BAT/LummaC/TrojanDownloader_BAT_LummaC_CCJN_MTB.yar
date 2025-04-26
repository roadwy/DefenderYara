
rule TrojanDownloader_BAT_LummaC_CCJN_MTB{
	meta:
		description = "TrojanDownloader:BAT/LummaC.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_81_0 = {6e 41 2b 37 45 50 4a 53 66 4f 31 4b 6c 71 4c 61 78 39 41 5a 75 67 3d 3d } //5 nA+7EPJSfO1KlqLax9AZug==
		$a_81_1 = {53 33 6f 6a 54 55 78 73 57 55 41 35 55 31 52 4b 52 6e 74 69 66 57 64 4b 62 45 77 3d } //5 S3ojTUxsWUA5U1RKRntifWdKbEw=
		$a_81_2 = {54 41 4f 48 6a 46 6e 4b 46 57 61 4c 56 37 7a 70 6c 4f 68 6e 6d 77 3d 3d } //1 TAOHjFnKFWaLV7zplOhnmw==
		$a_81_3 = {77 64 34 74 43 56 39 2f 31 42 62 50 56 75 6a 6f 52 6d 35 64 70 51 3d 3d } //1 wd4tCV9/1BbPVujoRm5dpQ==
		$a_81_4 = {66 73 4a 66 65 50 61 4c 39 50 68 71 58 4c 4b 50 30 6b 33 73 56 51 3d 3d } //1 fsJfePaL9PhqXLKP0k3sVQ==
		$a_81_5 = {56 57 6f 79 45 6b 67 50 68 2b 6f 54 6f 78 6c 50 6c 4b 37 73 56 77 3d 3d } //1 VWoyEkgPh+oToxlPlK7sVw==
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=14
 
}