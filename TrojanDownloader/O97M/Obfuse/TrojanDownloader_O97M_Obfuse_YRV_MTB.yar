
rule TrojanDownloader_O97M_Obfuse_YRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 20 3d 20 53 68 65 6c 6c 28 6f 64 73 75 6f 7a 6c 64 78 75 66 6d 28 22 35 30 22 29 20 26 20 6f 64 73 75 6f 7a 6c 64 78 75 66 6d 28 22 34 66 35 37 34 35 35 32 35 33 34 38 34 35 34 63 34 63 32 65 36 35 37 38 22 29 } //01 00  x = Shell(odsuozldxufm("50") & odsuozldxufm("4f5745525348454c4c2e6578")
		$a_01_1 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 67 77 6e 64 63 6f 77 71 79 75 6c 6b 2c 20 63 6a 7a 6b 71 6a 77 76 74 64 78 72 2c 20 32 29 } //01 00  Chr$(Val("&H" & Mid$(gwndcowqyulk, cjzkqjwvtdxr, 2)
		$a_01_2 = {3d 20 31 20 54 6f 20 4c 65 6e 28 67 77 6e 64 63 6f 77 71 79 75 6c 6b 29 20 53 74 65 70 20 32 } //01 00  = 1 To Len(gwndcowqyulk) Step 2
		$a_01_3 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //00 00  Sub Auto_Open()
	condition:
		any of ($a_*)
 
}