
rule TrojanDownloader_Win32_VB_XQ{
	meta:
		description = "TrojanDownloader:Win32/VB.XQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 55 73 65 65 4d 6f 4b 75 61 69 00 } //01 00  啕敳䵥䭯慵i
		$a_01_1 = {41 76 61 6e 74 4d 6f 4b 75 61 69 00 } //01 00  癁湡䵴䭯慵i
		$a_00_2 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 73 00 68 00 61 00 72 00 65 00 64 00 61 00 63 00 63 00 65 00 73 00 73 00 74 00 00 00 } //01 00 
		$a_01_3 = {50 61 6e 44 75 61 6e 54 69 6d 65 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}