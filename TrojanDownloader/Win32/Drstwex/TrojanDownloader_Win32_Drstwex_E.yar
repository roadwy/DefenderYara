
rule TrojanDownloader_Win32_Drstwex_E{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 8b 00 8b d0 c1 e0 03 33 c2 05 bd 04 00 00 5a 89 02 c1 e8 18 5a c3 } //01 00 
		$a_01_1 = {34 65 72 65 } //00 00  4ere
	condition:
		any of ($a_*)
 
}