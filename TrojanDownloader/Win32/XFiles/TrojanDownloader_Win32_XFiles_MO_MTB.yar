
rule TrojanDownloader_Win32_XFiles_MO_MTB{
	meta:
		description = "TrojanDownloader:Win32/XFiles.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 00 2e 00 72 00 75 00 6e 00 65 00 2d 00 73 00 70 00 65 00 63 00 74 00 72 00 61 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 } //01 00  x.rune-spectrals.com/torrent/uploads
		$a_01_1 = {7b 6b 67 66 76 66 66 66 66 66 6c } //01 00  {kgfvfffffl
		$a_01_2 = {66 7b 7b 6b 63 32 } //01 00  f{{kc2
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}