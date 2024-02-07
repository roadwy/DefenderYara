
rule TrojanDownloader_O97M_IcedID_PCK_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 30 63 61 31 39 39 64 2e 63 64 62 31 30 36 61 64 20 66 32 31 62 66 31 66 36 28 30 29 20 2b 20 22 20 22 20 2b 20 65 33 32 36 33 37 38 34 } //01 00  f0ca199d.cdb106ad f21bf1f6(0) + " " + e3263784
		$a_00_1 = {3d 20 53 70 6c 69 74 28 66 39 39 37 33 62 65 61 2c 20 22 7c 22 29 } //01 00  = Split(f9973bea, "|")
		$a_00_2 = {61 65 66 66 34 61 62 34 2e 65 78 65 63 28 66 34 31 66 35 34 61 36 29 } //00 00  aeff4ab4.exec(f41f54a6)
	condition:
		any of ($a_*)
 
}