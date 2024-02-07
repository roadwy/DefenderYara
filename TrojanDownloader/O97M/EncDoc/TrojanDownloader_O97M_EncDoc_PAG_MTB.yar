
rule TrojanDownloader_O97M_EncDoc_PAG_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 6d 62 63 22 } //01 00  vb_name="mbc"
		$a_01_1 = {22 77 63 69 6b 3d 77 63 69 6b 26 22 65 38 61 71 71 62 62 61 68 6f 61 71 71 62 64 61 64 67 61 71 71 62 6a 61 68 63 61 71 67 62 32 61 65 65 61 71 77 } //01 00  "wcik=wcik&"e8aqqbbahoaqqbdadgaqqbjahcaqgb2aeeaqw
		$a_01_2 = {2e 72 75 6e 28 76 62 74 66 73 78 68 62 68 6b 62 6b 6e 65 68 64 70 63 76 73 70 6b 6b 71 6d 75 79 75 78 6d 66 68 72 66 70 73 2c 69 6c 6c 65 7a 73 66 68 75 62 68 64 6d 6b 66 6a 68 76 73 74 76 66 68 72 6b 7a 76 77 6c 6e 29 } //01 00  .run(vbtfsxhbhkbknehdpcvspkkqmuyuxmfhrfps,illezsfhubhdmkfjhvstvfhrkzvwln)
		$a_01_3 = {6b 75 69 3d 63 68 72 28 66 73 63 76 2d 31 32 31 29 } //00 00  kui=chr(fscv-121)
	condition:
		any of ($a_*)
 
}