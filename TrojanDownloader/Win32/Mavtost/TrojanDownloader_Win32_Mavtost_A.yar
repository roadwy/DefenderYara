
rule TrojanDownloader_Win32_Mavtost_A{
	meta:
		description = "TrojanDownloader:Win32/Mavtost.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {32 06 2a 45 74 fe c8 ff 45 74 88 04 0a 41 39 7d 74 72 e7 } //03 00 
		$a_00_1 = {32 c2 2a c1 fe c8 88 04 2e 41 46 3b cf 72 eb } //02 00 
		$a_02_2 = {30 0c 30 8b 0d 90 02 04 8a 49 02 0f b6 d9 40 81 90 01 01 24 6d 00 00 3b c3 90 00 } //02 00 
		$a_02_3 = {30 0c 10 a1 90 02 04 8a 48 02 0f b6 c1 42 05 90 01 01 6d 00 00 3b d0 90 00 } //01 00 
		$a_00_4 = {4b 72 79 70 74 6f 6e } //01 00 
		$a_00_5 = {6d 61 73 74 65 72 68 6f 73 74 31 32 32 } //00 00 
		$a_00_6 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}