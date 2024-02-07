
rule TrojanDownloader_O97M_Obfuse_AK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 33 20 3d 20 52 65 70 6c 61 63 65 28 4a 6f 69 6e 28 71 54 2c 20 22 22 29 2c 20 6b 6d 2c 20 22 22 29 } //01 00  o3 = Replace(Join(qT, ""), km, "")
		$a_01_1 = {71 54 20 3d 20 53 70 6c 69 74 28 6f 33 2c 20 43 42 29 } //01 00  qT = Split(o3, CB)
		$a_01_2 = {52 52 2e 4b 20 22 72 65 67 73 76 72 22 20 26 20 33 32 20 26 20 22 20 22 20 26 20 45 28 49 2c 20 31 29 } //01 00  RR.K "regsvr" & 32 & " " & E(I, 1)
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 50 36 2c 20 6d 63 2c 20 30 2c 20 30 } //00 00  URLDownloadToFile 0, P6, mc, 0, 0
	condition:
		any of ($a_*)
 
}