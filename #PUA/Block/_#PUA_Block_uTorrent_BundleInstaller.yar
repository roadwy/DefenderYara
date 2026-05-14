
rule _#PUA_Block_uTorrent_BundleInstaller{
	meta:
		description = "!#PUA:Block:uTorrent_BundleInstaller,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {62 61 62 79 6c 6f 6e } //1 babylon
		$a_81_1 = {64 32 7a 30 39 35 76 65 78 62 74 66 76 69 } //1 d2z095vexbtfvi
		$a_81_2 = {69 6e 74 65 6c 6c 69 64 6f 77 6e 6c 6f 61 64 } //2 intellidownload
		$a_81_3 = {76 69 64 65 6f 66 69 6c 65 64 6f 77 6e 6c 6f 61 64 } //2 videofiledownload
		$a_81_4 = {53 74 61 72 74 53 65 61 72 63 68 65 72 } //1 StartSearcher
		$a_81_5 = {54 6f 72 72 65 6e 74 53 65 61 72 63 68 } //1 TorrentSearch
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}