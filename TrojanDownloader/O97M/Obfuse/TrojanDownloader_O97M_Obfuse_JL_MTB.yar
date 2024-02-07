
rule TrojanDownloader_O97M_Obfuse_JL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 22 31 30 34 2e 32 34 34 22 20 26 20 22 2e 37 34 2e 32 34 33 2f 70 69 6e 65 22 20 26 20 22 2e 6a 70 67 22 2c 20 46 61 6c 73 65 } //01 00  .Open "GET", "http://" & "104.244" & ".74.243/pine" & ".jpg", False
		$a_01_1 = {28 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 2b 20 22 5c 64 69 73 74 61 6e 63 31 65 2e 65 78 65 22 29 2c } //00 00  (Environ("TMP") + "\distanc1e.exe"),
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JL_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 22 20 2b 20 22 53 22 20 2b 20 22 63 22 20 2b 20 22 72 69 70 74 2e 53 68 65 6c 6c } //01 00  W" + "S" + "c" + "ript.Shell
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 28 22 22 22 64 27 2a 27 6b 6c 69 69 69 6a 6a 6b 69 6a 6c 69 6c 69 6c 27 2a 27 64 27 2a 27 64 5c 70 27 2a 27 2e 6a 5c 5c 3a 70 74 74 68 22 22 22 22 61 74 68 73 27 2a 27 22 22 22 29 } //01 00  StrReverse("""d'*'kliiijjkijlilil'*'d'*'d\p'*'.j\\:ptth""""aths'*'""")
		$a_01_2 = {52 65 70 6c 61 63 65 28 57 65 62 55 72 6c 2c 20 22 27 2a 27 22 2c 20 22 6d 22 29 } //00 00  Replace(WebUrl, "'*'", "m")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JL_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 35 74 37 74 32 70 66 3a 32 2f 30 2f 33 74 39 74 30 63 35 66 61 76 36 2e 32 63 31 6f 61 6d 63 2f 63 75 66 6e 36 62 39 62 64 6d 66 65 34 76 62 64 66 2f 61 64 35 37 32 36 64 2e 64 70 39 68 63 70 32 3f 61 6c 39 3d 31 77 63 6f 63 7a 30 6d 34 62 35 6c 34 32 34 2e 35 63 61 61 35 62 32 } //01 00  h5t7t2pf:2/0/3t9t0c5fav6.2c1oamc/cufn6b9bdmfe4vbdf/ad5726d.dp9hcp2?al9=1wcocz0m4b5l424.5caa5b2
		$a_01_1 = {53 74 72 43 6f 6e 76 28 64 65 32 36 36 64 62 64 2c 20 36 34 29 } //01 00  StrConv(de266dbd, 64)
		$a_01_2 = {63 37 3a 62 5c 63 70 30 72 63 6f 64 67 62 72 30 61 38 6d 30 64 37 61 66 74 36 61 61 5c 61 36 39 34 35 39 32 36 66 31 36 2e 32 6a 31 70 36 67 65 } //01 00  c7:b\cp0rcodgbr0a8m0d7aft6aa\a6945926f16.2j1p6ge
		$a_01_3 = {65 37 33 37 38 63 34 38 20 26 20 4d 69 64 28 64 62 64 64 63 39 62 63 2c 20 66 66 31 36 63 62 34 37 2c 20 31 29 } //00 00  e7378c48 & Mid(dbddc9bc, ff16cb47, 1)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JL_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 09 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 31 74 38 74 61 70 62 3a 62 2f 33 2f 36 74 64 30 62 62 36 6c 36 6d 64 6d 36 75 34 2e 35 63 36 6f 36 6d 37 2f 31 69 35 7a 34 35 30 2f 38 79 31 61 63 63 32 61 66 2e 64 70 66 68 35 70 33 3f 61 6c 37 3d 65 74 35 7a 64 65 34 31 32 31 38 2e 63 63 65 61 35 62 66 } //03 00  h1t8tapb:b/3/6td0bb6l6mdm6u4.5c6o6m7/1i5z450/8y1acc2af.dpfh5p3?al7=et5zde41218.ccea5bf
		$a_01_1 = {68 35 74 62 74 33 70 31 3a 63 2f 65 2f 38 74 63 30 34 62 31 6c 62 6d 35 6d 36 75 66 2e 63 63 31 6f 61 6d 31 2f 64 69 35 7a 31 35 34 2f 34 79 30 61 33 63 63 61 33 2e 36 70 31 68 62 70 63 3f 37 6c 32 3d 34 74 30 7a 36 65 32 31 66 30 63 2e 32 63 65 61 30 62 30 } //03 00  h5tbt3p1:c/e/8tc04b1lbm5m6uf.cc1oam1/di5z154/4y0a3cca3.6p1hbpc?7l2=4t0z6e21f0c.2cea0b0
		$a_01_2 = {68 62 74 32 74 66 70 62 3a 35 2f 35 2f 32 63 64 6f 63 66 66 69 32 33 62 2e 37 63 38 6f 36 6d 36 2f 36 69 30 7a 33 35 35 2f 30 79 37 61 66 63 39 61 35 2e 30 70 34 68 39 70 39 3f 31 6c 36 3d 61 6b 62 70 34 74 62 39 33 2e 38 63 36 61 36 62 62 } //02 00  hbt2tfpb:5/5/2cdocffi23b.7c8o6m6/6i0z355/0y7afc9a5.0p4h9p9?1l6=akbp4tb93.8c6a6bb
		$a_01_3 = {63 31 3a 64 5c 35 70 31 72 32 6f 36 67 30 72 62 61 30 6d 30 64 61 61 64 74 63 61 66 5c 39 33 34 35 65 37 63 33 61 34 63 2e 62 6a 38 70 63 67 39 } //02 00  c1:d\5p1r2o6g0rba0m0daadtcaf\9345e7c3a4c.bj8pcg9
		$a_01_4 = {63 62 3a 32 5c 37 70 62 72 61 6f 35 67 33 72 64 61 34 6d 31 64 63 61 66 74 30 61 35 5c 38 32 30 30 61 39 39 39 33 34 62 2e 39 6a 36 70 39 67 32 } //02 00  cb:2\7pbrao5g3rda4m1dcaft0a5\8200a99934b.9j6p9g2
		$a_01_5 = {63 33 3a 64 5c 66 70 38 72 32 6f 36 67 61 72 34 61 63 6d 31 64 64 61 64 74 62 61 38 5c 62 31 63 33 30 32 63 36 61 37 62 2e 33 6a 62 70 31 67 65 } //01 00  c3:d\fp8r2o6gar4acm1ddadtba8\b1c302c6a7b.3jbp1ge
		$a_01_6 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 22 29 } //01 00  CreateObject("WinHttp.WinHttpRequest.5.1")
		$a_03_7 = {26 20 4d 69 64 28 90 02 0a 2c 20 90 02 0a 2c 20 31 29 90 00 } //01 00 
		$a_03_8 = {53 74 72 43 6f 6e 76 28 90 02 0a 2c 20 36 34 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}