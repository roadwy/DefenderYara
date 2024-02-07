
rule TrojanDownloader_O97M_Obfuse_QL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 37 68 69 67 6d 34 57 34 45 20 3d 20 4b 37 68 69 67 6d 34 57 34 45 20 26 20 36 2e 35 30 32 31 37 33 34 37 37 33 39 20 2f 20 51 42 43 6f 6c 6f 72 28 39 2e 36 35 36 31 37 31 35 38 36 36 33 20 26 20 32 36 30 38 37 2e 39 30 33 31 34 31 35 37 34 32 20 2f 20 68 67 4a 4f 59 55 29 } //01 00  K7higm4W4E = K7higm4W4E & 6.50217347739 / QBColor(9.65617158663 & 26087.9031415742 / hgJOYU)
		$a_01_1 = {2e 63 6d 64 22 2c 20 54 72 75 65 29 } //01 00  .cmd", True)
		$a_01_2 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 43 72 65 64 69 74 42 6c 61 6e 6b 2e 50 61 67 65 44 65 70 6f 73 69 74 2e 43 61 70 74 69 6f 6e 29 } //00 00  .WriteLine (CreditBlank.PageDeposit.Caption)
	condition:
		any of ($a_*)
 
}