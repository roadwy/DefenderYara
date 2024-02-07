
rule TrojanDownloader_O97M_Powdow_RVCG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 33 39 38 30 5f 76 6e 69 2f 6d 6f 63 2e 6d 61 6b 63 69 6c 63 74 73 75 6a 2f 2f 3a 70 74 74 68 } //01 00  exe.3980_vni/moc.makcilctsuj//:ptth
		$a_01_1 = {64 6f 79 66 66 2e 72 75 6e 22 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 2b 6a 65 66 72 61 63 69 69 78 61 7a 79 6f 74 70 2b 22 22 2b 66 6a 77 76 74 6f } //01 00  doyff.run"certutil.exe-urlcache-split-f"+jefraciixazyotp+""+fjwvto
		$a_01_2 = {61 75 74 6f 5f 6f 70 65 6e 28 29 } //00 00  auto_open()
	condition:
		any of ($a_*)
 
}