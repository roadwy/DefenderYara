
rule TrojanDownloader_Win32_Debaox_A_ms{
	meta:
		description = "TrojanDownloader:Win32/Debaox.A!ms,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 14 18 8a 12 90 01 02 80 f2 90 01 01 8d 0c 18 88 11 90 01 02 40 3d 90 01 04 75 90 00 } //00 00 
		$a_00_1 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}