
rule TrojanDownloader_BAT_Banload_M{
	meta:
		description = "TrojanDownloader:BAT/Banload.M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 63 6f 30 33 2e 65 78 65 } //01 00  Tco03.exe
		$a_01_1 = {53 65 72 76 65 72 43 6f 6d 70 75 74 65 72 00 4e 65 74 77 6f 72 6b 00 67 65 74 5f 4e 65 74 77 6f 72 6b 00 50 69 6e 67 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  敓癲牥潃灭瑵牥一瑥潷歲最瑥也瑥潷歲倀湩g潄湷潬摡楆敬
		$a_01_2 = {2e 00 65 00 78 00 65 00 00 23 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}