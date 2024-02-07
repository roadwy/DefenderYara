
rule TrojanDownloader_O97M_Ursnif_PDUB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.PDUB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 6b 46 6f 6e 64 61 28 63 56 61 6c 75 74 65 28 22 49 68 73 66 73 2e 29 3f 74 3a 69 74 63 3d 45 70 2f 72 72 6d 52 45 74 2f 65 61 6f 22 29 2c 20 6d 29 } //01 00  = kFonda(cValute("Ihsfs.)?t:itc=Ep/rrmREt/eao"), m)
		$a_01_1 = {66 4c 6f 67 69 63 61 20 3d 20 55 41 72 65 73 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e } //01 00  fLogica = UAres & Application.
		$a_01_2 = {3d 20 56 42 41 2e 45 6e 76 69 72 6f 6e 28 28 28 22 54 45 6d 70 22 29 29 29 20 26 20 22 5c 22 } //01 00  = VBA.Environ((("TEmp"))) & "\"
		$a_01_3 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 66 61 29 2e 47 65 74 28 6e 6e 74 29 } //01 00  = GetObject(fa).Get(nnt)
		$a_01_4 = {2e 4f 70 65 6e 20 22 22 20 26 20 52 59 2c 20 56 69 55 2c 20 46 61 6c 73 65 2c 20 22 22 2c 20 22 22 } //00 00  .Open "" & RY, ViU, False, "", ""
	condition:
		any of ($a_*)
 
}