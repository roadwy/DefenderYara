
rule TrojanDownloader_Win32_Injector_B{
	meta:
		description = "TrojanDownloader:Win32/Injector.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 32 70 70 70 2e 63 6f 6d } //01 00 
		$a_03_1 = {6a ff 6a 18 6a 0d 6a 0e 6a 06 6a 06 68 d4 07 00 00 8d 4d 90 01 01 c6 85 90 01 02 ff ff 07 90 00 } //01 00 
		$a_03_2 = {8b 70 08 8b 3d 90 01 02 40 00 68 90 01 02 40 00 68 83 00 00 00 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}