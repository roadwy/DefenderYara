
rule TrojanDownloader_Win32_Branvine_A{
	meta:
		description = "TrojanDownloader:Win32/Branvine.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {30 1c 30 40 3b c1 7c f4 } //01 00 
		$a_01_1 = {6a 02 55 68 00 ff ff ff 57 } //01 00 
		$a_01_2 = {6a 02 57 68 00 ff ff ff 56 } //01 00 
		$a_01_3 = {53 56 39 29 00 7c 00 } //00 00 
	condition:
		any of ($a_*)
 
}