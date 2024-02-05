
rule TrojanDownloader_Win32_Cutwail_BC{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 48 50 51 8b 55 fc 8b 42 34 50 8b 8d 90 01 04 51 ff 15 90 00 } //01 00 
		$a_01_1 = {8b 55 08 03 55 fc 0f b6 02 83 f0 } //00 00 
	condition:
		any of ($a_*)
 
}