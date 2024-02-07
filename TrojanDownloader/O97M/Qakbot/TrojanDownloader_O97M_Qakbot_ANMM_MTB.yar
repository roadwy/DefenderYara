
rule TrojanDownloader_O97M_Qakbot_ANMM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.ANMM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 49 31 32 22 29 20 3d 20 22 46 72 69 73 6b 6f 73 } //01 00  Sheets("Nosto").Range("I12") = "Friskos
		$a_01_1 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 31 30 22 29 20 3d 20 22 3d 46 72 69 73 6b 6f 73 28 30 2c 48 32 34 26 4b 31 37 26 4b 31 38 2c 47 31 30 2c 30 2c 30 29 } //01 00  Sheets("Nosto").Range("H10") = "=Friskos(0,H24&K17&K18,G10,0,0)
		$a_01_2 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 31 31 22 29 20 3d 20 22 3d 46 72 69 73 6b 6f 73 28 30 2c 48 32 35 26 4b 31 37 26 4b 31 38 2c 47 31 31 2c 30 2c 30 29 } //01 00  Sheets("Nosto").Range("H11") = "=Friskos(0,H25&K17&K18,G11,0,0)
		$a_01_3 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 31 32 22 29 20 3d 20 22 3d 46 72 69 73 6b 6f 73 28 30 2c 48 32 36 26 4b 31 37 26 4b 31 38 2c 47 31 32 2c 30 2c 30 29 } //00 00  Sheets("Nosto").Range("H12") = "=Friskos(0,H26&K17&K18,G12,0,0)
	condition:
		any of ($a_*)
 
}