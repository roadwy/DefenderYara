
rule TrojanDownloader_WinNT_Classloader_E{
	meta:
		description = "TrojanDownloader:WinNT/Classloader.E,SIGNATURE_TYPE_JAVAHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {63 2e 41 74 6f 6d [61-7a] [61-7a] [61-7a] [61-7a] [61-7a] [61-7a] 90 05 06 03 61 2d 7a 69 63 52 65 66 90 1b 00 90 1b 01 65 72 65 6e [0-ff] 67 65 74 [0-04] 90 1b 00 90 1b 01 [0-06] 4c 6f 61 64 65 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}