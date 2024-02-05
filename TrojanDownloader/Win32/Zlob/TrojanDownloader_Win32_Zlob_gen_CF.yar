
rule TrojanDownloader_Win32_Zlob_gen_CF{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 c6 84 24 90 01 04 90 03 01 01 45 54 90 09 0f 00 c6 84 24 90 00 } //01 00 
		$a_03_1 = {ff 47 c6 85 90 01 02 ff ff 45 90 09 05 00 c6 85 90 01 02 ff 90 00 } //02 00 
		$a_01_2 = {6d 67 72 74 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}