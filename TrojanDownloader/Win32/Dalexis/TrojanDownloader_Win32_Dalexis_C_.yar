
rule TrojanDownloader_Win32_Dalexis_C_{
	meta:
		description = "TrojanDownloader:Win32/Dalexis.C!!Dalexis,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8d 34 03 8a 0e 8d 54 3d f0 8a 02 32 c8 32 c1 47 88 0e 88 02 83 ff 10 75 02 33 ff } //01 00 
		$a_00_1 = {47 00 45 00 54 00 00 00 25 00 73 00 25 00 64 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_2 = {25 00 73 00 74 00 65 00 6d 00 70 00 5f 00 63 00 61 00 62 00 5f 00 25 00 64 00 2e 00 63 00 61 00 62 00 } //00 00  %stemp_cab_%d.cab
	condition:
		any of ($a_*)
 
}