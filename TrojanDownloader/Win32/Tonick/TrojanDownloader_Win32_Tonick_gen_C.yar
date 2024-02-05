
rule TrojanDownloader_Win32_Tonick_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Tonick.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,11 00 10 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 71 00 60 00 6b 00 6b 00 60 00 6e 00 6f 00 27 00 6f 00 73 00 69 00 } //01 00 
		$a_01_1 = {72 00 67 00 71 00 72 00 6c 00 65 00 62 00 7b 00 27 00 6f 00 73 00 69 00 } //05 00 
		$a_00_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //0a 00 
		$a_03_3 = {6b 70 ff fb 12 e7 0b 90 01 01 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c 90 01 02 00 07 f4 01 70 70 ff 1e 90 01 02 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}