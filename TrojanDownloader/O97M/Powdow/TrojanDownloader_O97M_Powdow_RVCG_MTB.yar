
rule TrojanDownloader_O97M_Powdow_RVCG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 33 39 38 30 5f 76 6e 69 2f 6d 6f 63 2e 6d 61 6b 63 69 6c 63 74 73 75 6a 2f 2f 3a 70 74 74 68 } //1 exe.3980_vni/moc.makcilctsuj//:ptth
		$a_01_1 = {64 6f 79 66 66 2e 72 75 6e 22 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 2b 6a 65 66 72 61 63 69 69 78 61 7a 79 6f 74 70 2b 22 22 2b 66 6a 77 76 74 6f } //1 doyff.run"certutil.exe-urlcache-split-f"+jefraciixazyotp+""+fjwvto
		$a_01_2 = {61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 auto_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCG_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 6f 6e 74 65 75 64 6f 5f 65 78 65 63 75 74 65 6c 69 6e 6b 3d 22 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 64 6f 77 6e 6c 6f 61 64 2f ?? ?? ?? ?? ?? ?? ?? ?? 2f ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 63 6f 6e 74 65 75 64 6f 5f 65 78 65 63 75 74 65 31 30 3d 22 2d 6f 74 65 73 74 22 63 6f 6e 74 65 75 64 6f 5f 65 78 65 63 75 74 65 31 31 3d 22 2e 76 62 } //1
		$a_01_1 = {61 2e 72 75 6e 28 6a 6b 6c 65 29 2c 30 65 6e 64 73 75 62 } //1 a.run(jkle),0endsub
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}