
rule TrojanDownloader_Win32_Startpage_CA{
	meta:
		description = "TrojanDownloader:Win32/Startpage.CA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 04 83 f9 64 72 ef 68 d0 07 00 00 ff 15 90 01 04 39 5d f0 75 0a 68 03 40 00 80 90 00 } //01 00 
		$a_01_1 = {25 73 5c 31 32 32 38 2e 74 6d 70 } //01 00  %s\1228.tmp
		$a_03_2 = {2e 37 36 35 33 32 31 2e 69 6e 66 6f 3a 90 01 04 2f 73 6d 73 2f 78 78 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}