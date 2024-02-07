
rule TrojanDownloader_Win32_Meac_A{
	meta:
		description = "TrojanDownloader:Win32/Meac.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 00 2e 54 4d 50 c6 40 04 00 } //02 00 
		$a_01_1 = {c7 00 5c 4d 69 63 c7 40 04 4e 73 5c 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}