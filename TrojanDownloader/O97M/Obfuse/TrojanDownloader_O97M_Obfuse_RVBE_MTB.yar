
rule TrojanDownloader_O97M_Obfuse_RVBE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 43 65 6c 6c 73 28 31 30 36 2c 20 32 29 29 } //01 00  GetObject(Cells(106, 2))
		$a_01_1 = {3d 20 74 38 67 30 66 2e 4f 70 65 6e 28 76 30 64 66 20 2b 20 22 5c 55 72 68 6a 67 2e 62 61 74 22 29 } //01 00  = t8g0f.Open(v0df + "\Urhjg.bat")
		$a_01_2 = {22 43 3a 5c 55 73 65 72 73 5c 22 20 2b 20 71 61 58 47 69 28 29 2e 4e 61 6d 65 73 70 61 63 65 28 55 53 45 52 5f 50 52 4f 46 49 4c 45 29 } //01 00  "C:\Users\" + qaXGi().Namespace(USER_PROFILE)
		$a_01_3 = {72 65 76 20 26 20 4d 69 64 28 73 2c 20 70 2c 20 31 29 } //00 00  rev & Mid(s, p, 1)
	condition:
		any of ($a_*)
 
}