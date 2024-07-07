
rule TrojanDownloader_O97M_Dridex_VS_MSR{
	meta:
		description = "TrojanDownloader:O97M/Dridex.VS!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 65 73 70 6f 74 73 5f 73 74 65 65 76 65 73 74 5f 65 70 69 67 79 6e 6f 75 73 20 3d 20 52 65 70 6c 61 63 65 28 22 28 46 6f 50 6a 70 28 46 6f 50 6a 70 28 46 6f 50 6a 70 28 46 6f 50 6a 70 68 74 74 70 73 3a 2f 2f 69 6d 70 72 65 73 73 2d 68 72 64 2e 6d 79 73 6f 66 74 68 65 61 76 65 6e 2e 63 6f 6d 2f 46 56 65 6a 46 59 72 77 72 50 37 67 58 78 2e 70 68 70 22 2c 20 22 28 46 6f 50 6a 70 22 2c 20 22 22 29 } //1 respots_steevest_epigynous = Replace("(FoPjp(FoPjp(FoPjp(FoPjphttps://impress-hrd.mysoftheaven.com/FVejFYrwrP7gXx.php", "(FoPjp", "")
	condition:
		((#a_01_0  & 1)*1) >=1
 
}