
rule TrojanDownloader_O97M_Powdow_RVCF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 73 67 62 6f 78 22 65 72 72 6f 72 21 21 21 22 3a 5f 63 61 6c 6c 73 68 65 6c 6c 21 28 62 72 6f 6b 65 6e 73 68 6f 77 6f 66 66 29 65 6e 64 73 75 62 } //01 00  msgbox"error!!!":_callshell!(brokenshowoff)endsub
		$a_01_1 = {68 69 2e 78 78 78 2b 73 68 6f 77 6f 66 66 2e 6b 6f 6e 73 61 2b 73 68 6f 77 6f 66 66 2e 74 } //01 00  hi.xxx+showoff.konsa+showoff.t
		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //00 00  subworkbook_open()
	condition:
		any of ($a_*)
 
}