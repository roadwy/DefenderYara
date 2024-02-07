
rule TrojanDownloader_O97M_EncDoc_PAAX_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 30 73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 61 61 74 6a 67 73 64 76 66 70 63 76 65 77 72 65 6e 64 73 75 62 73 75 62 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 61 61 74 6a 67 73 64 76 66 70 63 76 65 77 72 65 6e 64 } //01 00  =0subauto_open()aatjgsdvfpcvewrendsubsubdocument_open()aatjgsdvfpcvewrend
		$a_01_1 = {62 34 31 34 37 34 35 34 31 35 36 34 31 34 32 36 38 22 29 61 65 61 64 64 6e 69 7a 71 72 7a 6e 3d 61 65 61 64 64 6e 69 7a 71 72 7a 6e 2b 69 6c 72 7a 78 66 77 77 69 6b 77 6f 28 22 34 31 34 33 34 31 34 31 34 62 34 31 34 31 36 62 34 31 34 35 36 62 34 31 35 36 36 37 34 31 37 32 34 31 34 33 35 31 34 31 35 33 37 37 34 31 37 30 34 31 22 29 26 69 6c 72 7a 78 66 77 77 69 6b 77 6f } //01 00  b4147454156414268")aeaddnizqrzn=aeaddnizqrzn+ilrzxfwwikwo("414341414b41416b41456b4156674172414351415377417041")&ilrzxfwwikwo
		$a_01_2 = {2e 63 72 65 61 74 65 61 65 61 64 64 6e 69 7a 71 72 7a 6e 2c 6e 75 6c 6c 2c 6b 61 68 77 68 61 68 79 68 64 74 61 79 79 6d 76 65 69 67 66 2c 69 6e 74 70 72 6f 63 65 73 73 69 64 65 6e 64 66 } //00 00  .createaeaddnizqrzn,null,kahwhahyhdtayymveigf,intprocessidendf
	condition:
		any of ($a_*)
 
}