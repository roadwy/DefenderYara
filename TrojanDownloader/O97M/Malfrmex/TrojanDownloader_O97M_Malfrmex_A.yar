
rule TrojanDownloader_O97M_Malfrmex_A{
	meta:
		description = "TrojanDownloader:O97M/Malfrmex.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 61 6c 6c 2e 65 22 20 26 20 22 78 65 22 2c 20 32 } //01 00  .savetofile "all.e" & "xe", 2
		$a_01_1 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 22 4d 45 53 53 41 47 45 28 54 72 75 65 2c 20 22 22 72 65 6c 65 61 73 65 22 22 29 22 } //00 00  ExecuteExcel4Macro "MESSAGE(True, ""release"")"
	condition:
		any of ($a_*)
 
}