
rule TrojanDownloader_Win32_Pedrp_A{
	meta:
		description = "TrojanDownloader:Win32/Pedrp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 6f 77 6e 20 66 69 6c 65 20 73 75 63 63 65 73 73 } //01 00  down file success
		$a_03_1 = {3c 0d 74 04 3c 0a 75 08 c6 84 14 90 01 01 00 00 00 00 80 bc 14 90 1b 00 00 00 00 2f 74 03 4a 79 dc 90 00 } //01 00 
		$a_03_2 = {ff d0 85 c0 74 0a c7 05 90 01 04 00 00 00 00 56 8b 35 90 01 04 57 68 90 01 04 8b 0e 6a 00 68 90 01 04 68 90 01 04 6a 00 56 ff 51 54 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}