
rule TrojanDownloader_Win32_Flosyt_A{
	meta:
		description = "TrojanDownloader:Win32/Flosyt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 6c 75 70 64 61 74 65 00 } //01 00 
		$a_00_1 = {2e 70 68 70 3f 61 63 74 69 6f 6e 3d 61 64 64 26 } //01 00  .php?action=add&
		$a_03_2 = {ff 75 08 e8 90 01 04 83 f8 2b 77 04 c9 c2 04 00 83 e8 2a 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}