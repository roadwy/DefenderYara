
rule TrojanDownloader_Linux_Bartallex_I{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.I,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 63 6f 79 6c 2e 63 22 20 26 20 22 6f 6d 2f 77 22 20 26 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 74 75 62 65 70 72 65 73 73 2d 63 6f 6e 74 65 6e 74 2f 22 } //2 tcoyl.c" & "om/w" & "p-content/tubepress-content/"
		$a_01_1 = {74 61 6d 65 6c 61 67 69 6c 62 65 72 74 6d 64 2e 63 22 20 26 20 22 6f 6d 2f 22 } //2 tamelagilbertmd.c" & "om/"
		$a_01_2 = {22 36 36 38 33 36 34 38 37 31 36 32 22 } //1 "66836487162"
		$a_01_3 = {22 2e 74 22 20 26 20 22 78 74 22 } //1 ".t" & "xt"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanDownloader_Linux_Bartallex_I_2{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.I,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 54 54 48 20 3d 20 43 68 72 28 4e 64 6a 73 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 31 32 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 31 32 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 38 29 20 26 20 } //1 ATTH = Chr(Ndjs) + Chr(Ndjs + 12) + Chr(Ndjs + 12) + Chr(Ndjs + 8) & 
		$a_01_1 = {54 53 54 53 20 3d 20 22 2e 22 20 2b 20 22 74 78 22 20 2b 20 22 74 22 } //1 TSTS = "." + "tx" + "t"
		$a_01_2 = {54 53 54 53 20 3d 20 22 22 20 26 20 22 2e 74 78 22 20 2b 20 22 74 22 20 2b 20 22 22 } //1 TSTS = "" & ".tx" + "t" + ""
		$a_01_3 = {4c 4e 53 53 20 3d 20 22 72 61 72 61 22 20 2b 20 54 53 54 53 } //1 LNSS = "rara" + TSTS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanDownloader_Linux_Bartallex_I_3{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.I,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_00_0 = {22 37 37 37 37 36 33 31 37 32 36 33 31 35 37 32 22 20 2b 20 54 53 54 53 } //1 "777763172631572" + TSTS
		$a_00_1 = {50 48 32 20 2b 20 4d 41 44 52 49 44 20 2b 20 22 2e 76 62 73 22 } //1 PH2 + MADRID + ".vbs"
		$a_00_2 = {28 4e 64 6a 73 20 2b 20 31 32 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 38 29 20 2b 20 22 3a 22 20 2b 20 22 2f 2f 22 } //1 (Ndjs + 12) + Chr(Ndjs + 8) + ":" + "//"
		$a_00_3 = {43 68 72 28 4e 64 6a 73 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 31 32 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 31 32 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 38 29 } //1 Chr(Ndjs) + Chr(Ndjs + 12) + Chr(Ndjs + 12) + Chr(Ndjs + 8)
		$a_00_4 = {43 44 44 44 20 3d 20 22 38 31 37 39 38 32 36 33 37 38 31 32 36 2e 74 78 74 22 } //1 CDDD = "8179826378126.txt"
		$a_00_5 = {47 47 47 52 20 3d 20 68 68 72 28 4e 64 6a 73 29 20 2b 20 68 68 72 28 4e 64 6a 73 } //1 GGGR = hhr(Ndjs) + hhr(Ndjs
		$a_00_6 = {47 45 46 4f 52 43 45 31 20 41 73 20 53 74 72 69 6e 67 2c 20 47 45 46 4f 52 43 45 32 20 41 73 20 53 74 72 69 6e 67 2c 20 68 64 6a 73 68 64 20 41 73 20 49 6e 74 65 67 65 72 } //1 GEFORCE1 As String, GEFORCE2 As String, hdjshd As Integer
		$a_00_7 = {4b 49 50 41 52 49 53 20 3d 20 4d 6f 64 75 6c 65 32 2e 68 68 72 28 } //1 KIPARIS = Module2.hhr(
		$a_00_8 = {43 53 74 72 28 49 6e 74 28 28 61 20 2f 20 32 20 2a 20 52 6e 64 29 20 2b 20 61 29 29 } //1 CStr(Int((a / 2 * Rnd) + a))
		$a_00_9 = {47 45 46 4f 52 43 45 31 20 3d 20 4d 69 64 28 43 4f 4e 54 32 2c 20 31 2c 20 69 20 2d 20 32 29 } //1 GEFORCE1 = Mid(CONT2, 1, i - 2)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=3
 
}