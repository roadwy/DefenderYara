
rule TrojanDownloader_O97M_Ursnif_RVE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.RVE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 66 61 6d 61 69 6c 65 28 22 59 66 2d 39 54 30 38 47 5f 33 45 22 29 2c 20 41 64 72 65 75 73 2c 20 46 61 6c 73 65 } //1 .Open famaile("Yf-9T08G_3E"), Adreus, False
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 66 61 6d 61 69 6c 65 28 22 5f 39 44 72 59 41 2e 61 38 44 53 6d 30 33 4f 74 2d 66 42 65 22 29 29 } //1 CreateObject(famaile("_9DrYA.a8DSm03Ot-fBe"))
		$a_01_2 = {46 6f 67 6c 69 6f 6f 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 28 62 69 6f 29 29 2e 47 65 74 28 28 65 6e 65 72 67 29 29 } //1 Foglioo = GetObject((bio)).Get((energ))
		$a_01_3 = {4d 69 64 24 28 63 4c 69 67 68 74 2c 20 6b 2c 20 31 29 } //1 Mid$(cLight, k, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Ursnif_RVE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.RVE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 5a 20 26 20 49 68 6f 6d 6d 29 } //1 = CreateObject(Z & Ihomm)
		$a_03_1 = {28 6e 69 75 28 31 30 2c 20 31 34 29 29 3a 20 90 02 05 20 3d 20 90 02 0a 28 6e 69 75 28 31 35 2c 20 32 31 29 29 90 00 } //1
		$a_01_2 = {71 41 71 75 61 2e 4f 70 65 6e 20 5a 20 26 20 6f 63 6d 6f 53 2c 20 73 4a 69 6d 6d 2c 20 46 61 6c 73 65 2c } //1 qAqua.Open Z & ocmoS, sJimm, False,
		$a_03_3 = {45 6e 76 69 72 6f 6e 90 02 01 28 28 28 6e 69 75 28 32 38 2c 20 32 39 29 29 29 29 20 26 20 22 5c 22 90 00 } //1
		$a_01_4 = {2e 57 72 69 74 65 20 71 41 71 75 61 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 3a 20 2e 53 61 76 65 54 6f 46 69 6c 65 20 68 6c 49 49 2c } //1 .Write qAqua.responseBody: .SaveToFile hlII,
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}