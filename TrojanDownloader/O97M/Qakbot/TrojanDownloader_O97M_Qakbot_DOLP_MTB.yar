
rule TrojanDownloader_O97M_Qakbot_DOLP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DOLP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 69 6f 20 3d 20 22 3d 4b 6f 70 61 73 74 } //1 Dio = "=Kopast
		$a_01_1 = {53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 52 61 6e 67 65 28 22 48 31 30 22 29 20 3d 20 44 69 6f 20 26 20 22 28 30 2c 48 32 34 26 4b 31 37 26 4b 31 38 2c 47 31 30 2c 30 2c 30 29 } //1 Sheets("Fikop").Range("H10") = Dio & "(0,H24&K17&K18,G10,0,0)
		$a_01_2 = {53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 52 61 6e 67 65 28 22 48 31 31 22 29 20 3d 20 44 69 6f 20 26 20 22 28 30 2c 48 32 35 26 4b 31 37 26 4b 31 38 2c 47 31 31 2c 30 2c 30 29 } //1 Sheets("Fikop").Range("H11") = Dio & "(0,H25&K17&K18,G11,0,0)
		$a_01_3 = {53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 52 61 6e 67 65 28 22 48 31 32 22 29 20 3d 20 44 69 6f 20 26 20 22 28 30 2c 48 32 36 26 4b 31 37 26 4b 31 38 2c 47 31 32 2c 30 2c 30 29 } //1 Sheets("Fikop").Range("H12") = Dio & "(0,H26&K17&K18,G12,0,0)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}