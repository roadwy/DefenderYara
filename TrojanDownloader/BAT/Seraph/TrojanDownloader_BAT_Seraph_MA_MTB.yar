
rule TrojanDownloader_BAT_Seraph_MA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {54 76 47 4f 78 49 42 44 35 72 } //1 TvGOxIBD5r
		$a_81_1 = {53 6c 65 65 70 } //1 Sleep
		$a_81_2 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_81_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_5 = {59 67 71 76 67 7a 68 } //1 Ygqvgzh
		$a_81_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 73 65 61 72 63 68 3f 6f 65 3d 75 74 66 38 26 69 65 3d 75 74 66 38 2e 2e 2e } //1 http://www.google.com/search?oe=utf8&ie=utf8...
		$a_81_7 = {30 30 36 31 35 30 65 30 2d 61 34 63 35 2d 34 65 66 37 2d 39 64 30 38 2d 33 38 37 64 31 39 30 39 66 33 61 66 } //1 006150e0-a4c5-4ef7-9d08-387d1909f3af
		$a_81_8 = {53 74 65 61 6d } //1 Steam
		$a_81_9 = {43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 CurrentDomain
		$a_81_10 = {52 65 67 69 73 74 65 72 50 6f 6f 6c } //1 RegisterPool
		$a_81_11 = {54 65 73 74 42 61 73 65 } //1 TestBase
		$a_81_12 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_13 = {72 65 73 70 6f 6e 73 65 53 74 61 74 75 73 } //1 responseStatus
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}