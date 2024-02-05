
rule TrojanClicker_Win32_Worbe{
	meta:
		description = "TrojanClicker:Win32/Worbe,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 55 10 83 c2 04 8b 02 85 c0 7c 06 32 45 0c 88 01 41 ff 4d 10 83 7d 10 00 7f e8 8b 90 09 09 00 5f 7e 21 8d 8d 90 01 02 ff ff 90 00 } //01 00 
		$a_01_1 = {2f 73 63 72 69 70 74 73 2f 77 6f 72 6b 65 72 2e 70 68 70 00 } //01 00 
		$a_01_2 = {61 63 74 69 6f 6e 3d 67 65 74 25 35 46 73 63 72 69 70 74 26 00 } //00 00 
	condition:
		any of ($a_*)
 
}