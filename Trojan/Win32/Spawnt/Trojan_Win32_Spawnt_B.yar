
rule Trojan_Win32_Spawnt_B{
	meta:
		description = "Trojan:Win32/Spawnt.B,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 5c 54 65 73 74 } //01 00  :\Test
		$a_01_1 = {4f 6c 78 55 5a 58 4e 30 } //04 00  OlxUZXN0
		$a_01_2 = {3a 46 6c 69 6e 63 68 65 64 } //04 00  :Flinched
		$a_01_3 = {4f 6b 5a 73 61 57 35 6a 61 47 56 6b } //06 00  OkZsaW5jaGVk
		$a_02_4 = {6c 64 72 2e 65 78 65 90 09 02 00 6e 90 0a 16 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 90 00 } //05 00 
		$a_03_5 = {6b c0 28 5d 01 c5 03 5d 0c 53 8d 6c 24 20 ff 75 00 90 03 05 04 ff 15 90 01 04 e8 90 01 04 ff 84 24 90 01 06 68 00 00 00 00 68 04 00 00 00 90 00 } //05 00 
		$a_03_6 = {81 fb 02 c4 97 70 75 3b e8 90 01 04 50 50 90 00 } //0a 00 
		$a_03_7 = {83 fb 02 7c 1d 8b 1d 90 01 04 83 fb 06 7f 12 8b 1d 90 01 04 83 fb 05 74 07 b8 01 00 00 00 eb 02 31 c0 21 c0 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}