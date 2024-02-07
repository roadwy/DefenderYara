
rule TrojanDownloader_O97M_EncDoc_PDL_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 5e 75 5e 72 6c 68 74 74 5e 70 3a 2f 2f 32 30 39 2e 31 32 37 2e 32 30 2e 31 33 2f 77 6f 6b 6e 33 63 34 71 64 66 39 2e 6a 5e 73 2d 6f 22 26 67 39 76 7a 26 22 3b 22 26 67 39 76 7a 2c 22 6e 33 63 34 71 64 66 39 22 2c 22 65 22 29 } //01 00  c^u^rlhtt^p://209.127.20.13/wokn3c4qdf9.j^s-o"&g9vz&";"&g9vz,"n3c4qdf9","e")
		$a_01_1 = {61 5f 64 5f 66 2c 6f 70 65 6e 75 72 6c 22 26 69 75 71 71 61 67 6e 70 38 6f 77 2c } //01 00  a_d_f,openurl"&iuqqagnp8ow,
		$a_01_2 = {3d 72 65 70 6c 61 63 65 28 22 40 6f 72 40 69 6c 65 73 22 2c 22 40 22 2c 22 66 22 29 72 65 63 6f 2e } //00 00  =replace("@or@iles","@","f")reco.
	condition:
		any of ($a_*)
 
}