
rule TrojanDownloader_O97M_Obfuse_UB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.UB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 63 62 63 66 66 65 63 62 64 63 62 63 62 63 62 66 65 65 62 62 66 66 64 64 62 64 62 64 61 5f 63 62 62 62 63 61 61 65 64 64 5f 61 63 65 66 65 66 61 65 63 63 65 61 62 64 63 65 64 66 64 65 62 62 63 63 63 63 65 66 63 65 61 66 65 66 65 63 64 62 63 65 61 63 63 65 2e 6a 73 } //01 00  fcbcffecbdcbcbcbfeebbffddbdbda_cbbbcaaedd_acefefaecceabdcedfdebbccccefceafefecdbceacce.js
		$a_01_1 = {65 65 66 66 66 63 65 62 62 62 65 62 65 61 62 63 64 66 62 66 66 64 63 65 61 65 63 61 65 64 62 63 61 65 62 65 65 66 5f 62 63 62 62 61 61 65 61 5f 65 62 66 63 61 65 62 65 62 65 64 61 62 61 62 64 61 66 61 61 62 61 64 65 63 61 61 64 61 66 66 61 64 62 66 65 62 63 64 66 65 65 61 61 66 2e 74 78 74 22 2c 20 54 72 75 65 } //01 00  eefffcebbbebeabcdfbffdceaecaedbcaebeef_bcbbaaea_ebfcaebebedababdafaabadecaadaffadbfebcdfeeaaf.txt", True
		$a_01_2 = {61 65 65 65 62 62 64 64 63 63 66 61 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 3b } //01 00  aeeebbddccfa.GetSpecialFolder(2);
		$a_01_3 = {63 61 65 66 61 65 64 2e 74 6f 53 74 72 69 6e 67 28 29 } //01 00  caefaed.toString()
		$a_03_4 = {4d 61 74 68 2e 61 62 73 28 90 02 0a 29 90 00 } //01 00 
		$a_01_5 = {2e 6c 65 6e 67 74 68 2d 31 } //00 00  .length-1
	condition:
		any of ($a_*)
 
}