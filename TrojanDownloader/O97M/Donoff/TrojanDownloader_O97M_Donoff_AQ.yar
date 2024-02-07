
rule TrojanDownloader_O97M_Donoff_AQ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AQ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 22 20 2b 20 22 69 70 74 2e 53 68 65 22 20 2b 20 4d 69 64 28 } //01 00  .CreateObject("WScr" + "ipt.She" + Mid(
		$a_00_1 = {45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 25 74 65 6d 70 25 22 29 } //01 00  ExpandEnvironmentStrings", VbMethod, "%temp%")
		$a_00_2 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 54 45 47 22 29 } //00 00  = StrReverse("TEG")
	condition:
		any of ($a_*)
 
}