
rule TrojanDownloader_Win32_Tobor_A{
	meta:
		description = "TrojanDownloader:Win32/Tobor.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 68 b8 0b 00 00 6a 64 51 c7 90 01 03 00 00 00 00 00 00 ff 15 90 00 } //01 00 
		$a_00_1 = {3a 5c 00 00 5c 00 00 00 2e 70 69 66 } //00 00 
	condition:
		any of ($a_*)
 
}