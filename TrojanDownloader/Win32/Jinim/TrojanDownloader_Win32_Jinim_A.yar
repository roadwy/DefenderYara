
rule TrojanDownloader_Win32_Jinim_A{
	meta:
		description = "TrojanDownloader:Win32/Jinim.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff 0f be 82 90 01 04 33 c9 8a 0d 90 01 04 33 c1 8b 95 ec fc ff ff 88 82 90 01 04 eb 9c 90 00 } //01 00 
		$a_01_1 = {2f 4d 69 6e 69 4a 53 2e 64 6c 6c 00 } //01 00 
		$a_01_2 = {00 25 73 3b 6e 65 77 20 44 6f 77 6e 6c 6f 61 64 65 72 28 27 25 73 27 2c 20 27 25 73 27 29 2e 46 69 72 65 28 29 3b 00 } //01 00 
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 52 65 61 6c 53 65 72 76 69 63 65 20 25 73 } //00 00 
		$a_00_4 = {5d 04 00 } //00 a2 
	condition:
		any of ($a_*)
 
}