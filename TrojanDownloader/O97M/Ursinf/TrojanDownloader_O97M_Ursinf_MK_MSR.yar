
rule TrojanDownloader_O97M_Ursinf_MK_MSR{
	meta:
		description = "TrojanDownloader:O97M/Ursinf.MK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,11 00 11 00 03 00 00 "
		
	strings :
		$a_80_0 = {67 70 20 3d 20 7a 44 2e 6b 54 28 22 74 6d 70 22 29 20 26 20 22 5c 48 56 2e 74 6d 70 22 } //gp = zD.kT("tmp") & "\HV.tmp"  5
		$a_80_1 = {7a 44 2e 79 20 22 62 61 63 2e 39 6b 6f 6e 3d 6c 3f 70 68 70 2e 70 32 33 69 30 6f 69 61 2f 35 38 6f 6c 30 32 65 77 2f 6d 6f 63 2e 38 66 6a 6a 66 62 62 2f 2f 3a 70 74 74 68 22 2c 20 67 70 } //zD.y "bac.9kon=l?php.p23i0oia/58ol02ew/moc.8fjjfbb//:ptth", gp  10
		$a_80_2 = {55 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 26 2c 20 53 74 72 52 65 76 65 72 73 65 28 63 35 29 2c 20 45 45 2c 20 30 26 2c 20 30 26 29 } //U = URLDownloadToFile(0&, StrReverse(c5), EE, 0&, 0&)  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*10+(#a_80_2  & 1)*2) >=17
 
}