
rule TrojanDownloader_Win32_Forebee_A{
	meta:
		description = "TrojanDownloader:Win32/Forebee.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 90 01 01 88 1c 08 40 3b c2 7c f2 90 00 } //01 00 
		$a_03_1 = {83 c1 4b 89 0d 90 01 02 40 00 8b ce e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}