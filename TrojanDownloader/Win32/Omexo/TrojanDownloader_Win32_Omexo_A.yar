
rule TrojanDownloader_Win32_Omexo_A{
	meta:
		description = "TrojanDownloader:Win32/Omexo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 0b 8b 51 50 52 50 ff 15 } //01 00 
		$a_03_1 = {0f b6 14 08 88 54 24 03 80 74 24 03 90 01 01 c0 4c 24 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}