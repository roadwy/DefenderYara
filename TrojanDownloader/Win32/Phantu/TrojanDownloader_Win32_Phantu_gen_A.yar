
rule TrojanDownloader_Win32_Phantu_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Phantu.gen!A,SIGNATURE_TYPE_PEHSTR,16 00 14 00 18 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
		$a_01_1 = {67 65 74 55 52 4c 53 } //1 getURLS
		$a_01_2 = {5a 6f 6d 62 69 65 5f 47 65 74 54 79 70 65 49 6e 66 6f 43 6f 75 6e 74 } //1 Zombie_GetTypeInfoCount
		$a_01_3 = {5a 6f 6d 62 69 65 5f 47 65 74 54 79 70 65 49 6e 66 6f } //1 Zombie_GetTypeInfo
		$a_01_4 = {74 00 72 00 79 00 69 00 6e 00 20 00 74 00 6f 00 20 00 72 00 65 00 67 00 20 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 2e 00 2e 00 } //1 tryin to reg window...
		$a_01_5 = {61 00 62 00 6f 00 75 00 74 00 3a 00 62 00 6c 00 61 00 6e 00 6b 00 2d 00 } //1 about:blank-
		$a_01_6 = {68 00 74 00 74 00 70 00 73 00 2d 00 } //1 https-
		$a_01_7 = {6e 00 6f 00 74 00 20 00 69 00 65 00 2c 00 20 00 62 00 75 00 74 00 3a 00 20 00 } //1 not ie, but: 
		$a_01_8 = {63 00 2e 00 70 00 68 00 70 00 3f 00 } //1 c.php?
		$a_01_9 = {74 00 68 00 69 00 73 00 20 00 69 00 73 00 20 00 61 00 20 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 75 00 61 00 6c 00 } //1 this is a contextual
		$a_01_10 = {54 00 6f 00 74 00 61 00 6c 00 4c 00 69 00 6e 00 6b 00 73 00 3d 00 } //1 TotalLinks=
		$a_01_11 = {4c 00 61 00 73 00 74 00 4c 00 69 00 6e 00 6b 00 3d 00 } //1 LastLink=
		$a_01_12 = {6b 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00 73 00 72 00 76 00 2e 00 6e 00 65 00 74 00 } //1 k.localsrv.net
		$a_01_13 = {73 00 65 00 74 00 74 00 69 00 6e 00 67 00 20 00 76 00 70 00 74 00 } //1 setting vpt
		$a_01_14 = {64 00 6f 00 20 00 61 00 63 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 } //1 do ac...............
		$a_01_15 = {63 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00 73 00 72 00 76 00 2e 00 6e 00 65 00 74 00 } //1 c.localsrv.net
		$a_01_16 = {64 00 6f 00 20 00 63 00 6c 00 6f 00 73 00 65 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 } //1 do close...............
		$a_01_17 = {73 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00 73 00 72 00 76 00 2e 00 6e 00 65 00 74 00 } //1 s.localsrv.net
		$a_01_18 = {73 00 68 00 6f 00 77 00 20 00 6e 00 6f 00 72 00 6d 00 61 00 6c 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 } //1 show normal...............
		$a_01_19 = {74 00 72 00 79 00 20 00 74 00 6f 00 20 00 70 00 6f 00 70 00 20 00 61 00 63 00 6c 00 69 00 6e 00 6b 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 21 00 } //1 try to pop aclink!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		$a_01_20 = {2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 49 00 45 00 4f 00 62 00 6a 00 5f 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 2d 00 2d 00 3e 00 } //1 ++++++IEObj_DocumentComplete-->
		$a_01_21 = {52 00 65 00 66 00 65 00 72 00 65 00 72 00 3a 00 20 00 } //1 Referer: 
		$a_01_22 = {6e 00 65 00 77 00 20 00 70 00 6f 00 70 00 3a 00 20 00 } //1 new pop: 
		$a_01_23 = {70 00 6f 00 70 00 20 00 76 00 69 00 73 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 } //1 pop vis...............
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1) >=20
 
}