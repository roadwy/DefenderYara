
rule TrojanDownloader_O97M_Powdow_RVAN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 42 53 2e 63 6f 70 79 66 69 6c 65 20 61 64 6f 6f 2c 20 45 6e 76 69 72 6f 6e 24 28 6a 61 6c 75 6b 61 29 20 26 20 22 5c 6c 6f 22 20 2b 20 22 76 65 2e 63 6f 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 6d 22 29 2c 20 54 72 75 65 } //1 FBS.copyfile adoo, Environ$(jaluka) & "\lo" + "ve.co" + String(1, "m"), True
		$a_01_1 = {53 68 65 6c 6c 20 79 65 61 68 } //1 Shell yeah
		$a_01_2 = {72 65 73 74 69 6e 70 65 61 63 65 20 3d 20 4a 6f 69 6e 28 63 6f 6f 70 65 72 2c 20 22 22 29 20 2b 20 69 64 63 61 72 64 73 20 2b 20 22 } //1 restinpeace = Join(cooper, "") + idcards + "
		$a_01_3 = {6b 75 6c 69 6c 69 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 20 2b 20 53 70 61 63 65 28 32 29 20 2b 20 75 75 } //1 kulili.TextBox1.Value + Space(2) + uu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}