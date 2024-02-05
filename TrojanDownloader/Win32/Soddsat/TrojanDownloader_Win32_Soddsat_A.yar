
rule TrojanDownloader_Win32_Soddsat_A{
	meta:
		description = "TrojanDownloader:Win32/Soddsat.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 85 c0 75 05 b8 90 01 04 50 68 04 00 00 80 6a 00 68 90 01 04 68 02 00 00 00 bb 6c 02 00 00 e8 90 00 } //01 00 
		$a_01_1 = {44 3a 5c 77 69 6e 64 6f 73 2e 64 61 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}