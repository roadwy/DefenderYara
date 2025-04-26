
rule TrojanDownloader_O97M_IcedId_BI_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedId.BI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 2c 3a 2c 5c 2c 6a 2c 76 2c 61 2c 71 2c 62 2c 6a 2c 66 2c 5c 2c 66 2c 6c 2c 66 2c 67 2c 72 2c 7a 2c 33 2c 32 2c 5c 2c 7a 2c 66 2c 75 2c 67 2c 6e 2c 2e 2c 72 2c 6b 2c 72 2c 22 } //1 = "p,:,\,j,v,a,q,b,j,f,\,f,l,f,g,r,z,3,2,\,z,f,u,g,n,.,r,k,r,"
		$a_01_1 = {3d 20 61 5a 66 6c 32 57 28 52 65 70 6c 61 63 65 28 61 79 5a 49 6d 2c 20 61 4e 4a 32 52 6e 2c 20 22 22 29 29 } //1 = aZfl2W(Replace(ayZIm, aNJ2Rn, ""))
		$a_01_2 = {61 74 62 75 52 63 2e 65 78 65 63 20 61 4f 6c 34 42 68 } //1 atbuRc.exec aOl4Bh
		$a_01_3 = {61 52 31 55 68 20 28 61 47 52 39 62 20 26 20 22 20 22 20 26 20 61 35 52 58 6a 29 } //1 aR1Uh (aGR9b & " " & a5RXj)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_IcedId_BI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/IcedId.BI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = CreateObject("wscript.shell")
		$a_01_1 = {62 31 65 66 63 34 37 61 2e 66 30 34 37 63 61 36 39 20 66 33 39 65 39 33 30 61 28 30 29 20 2b 20 22 20 22 20 2b 20 66 35 32 34 34 32 30 38 } //1 b1efc47a.f047ca69 f39e930a(0) + " " + f5244208
		$a_01_2 = {43 61 6c 6c 20 61 66 38 61 33 30 31 61 2e 65 78 65 63 28 66 30 30 33 32 63 35 66 29 } //1 Call af8a301a.exec(f0032c5f)
		$a_01_3 = {3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 64 30 65 36 63 64 64 65 29 2e 54 69 74 6c 65 2c 20 22 7c 22 29 } //1 = Split(ActiveDocument.Shapes(d0e6cdde).Title, "|")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_IcedId_BI_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/IcedId.BI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = CreateObject("wscript.shell")
		$a_01_1 = {64 66 36 64 65 65 35 61 2e 66 37 34 31 33 35 30 34 20 63 63 62 31 32 37 37 33 28 30 29 20 2b 20 22 20 22 20 2b 20 66 37 36 34 37 61 31 37 } //1 df6dee5a.f7413504 ccb12773(0) + " " + f7647a17
		$a_01_2 = {43 61 6c 6c 20 64 37 33 63 30 61 66 63 2e 65 78 65 63 28 62 35 31 30 38 61 66 36 29 } //1 Call d73c0afc.exec(b5108af6)
		$a_01_3 = {3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 63 30 37 65 30 37 33 38 29 2e 54 69 74 6c 65 2c 20 22 7c 22 29 } //1 = Split(ActiveDocument.Shapes(c07e0738).Title, "|")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}