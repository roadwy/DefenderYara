
rule TrojanDownloader_Win32_Skidlo_B{
	meta:
		description = "TrojanDownloader:Win32/Skidlo.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6f 74 5f 69 64 22 3a 22 25 73 22 2c 22 76 65 72 73 69 6f 6e 22 3a } //01 00 
		$a_01_1 = {69 6e 64 65 78 2e 70 68 70 3f 72 3d 6c 6f 67 00 } //01 00 
		$a_01_2 = {66 ad 84 c0 74 11 3c 41 72 06 3c 5a 77 02 0c 20 c1 c2 03 32 d0 eb e9 } //01 00 
		$a_03_3 = {e8 00 00 00 00 5d 81 ed 90 01 04 bb c0 e6 0a b3 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}