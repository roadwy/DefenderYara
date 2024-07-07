
rule TrojanDownloader_O97M_Trickbot_C{
	meta:
		description = "TrojanDownloader:O97M/Trickbot.C,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 69 61 6c 5f 73 63 72 75 62 5f 6d 75 6c 74 69 20 73 75 62 32 2c 20 41 52 47 32 2c 20 61 64 64 70 65 72 34 } //1 dial_scrub_multi sub2, ARG2, addper4
		$a_00_1 = {64 69 61 6c 5f 73 63 72 75 62 5f 6d 75 6c 74 69 20 62 31 2c 20 63 6f 6e 74 72 6f 6c 2c 20 41 63 74 69 76 65 43 65 6c 6c 49 6e 54 61 62 6c 65 } //1 dial_scrub_multi b1, control, ActiveCellInTable
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}