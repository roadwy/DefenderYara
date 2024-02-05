
rule TrojanDownloader_Win32_Hoptto_B{
	meta:
		description = "TrojanDownloader:Win32/Hoptto.B,SIGNATURE_TYPE_PEHSTR_EXT,fffffffe 01 ffffffa4 01 07 00 00 ffffffc8 00 "
		
	strings :
		$a_01_0 = {31 34 32 2e 30 2e 33 36 2e 33 34 2f } //64 00 
		$a_01_1 = {6d 69 6e 65 72 2e 64 6c 6c } //64 00 
		$a_01_2 = {75 73 66 74 5f 65 78 74 2e 74 78 74 } //c8 00 
		$a_01_3 = {85 ff 7e 4e bb 01 00 00 00 8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 } //0a 00 
		$a_01_4 = {2f 6d 61 69 6e 2e 74 78 74 } //0a 00 
		$a_01_5 = {70 68 61 74 6b 2e 74 78 74 } //64 00 
		$a_01_6 = {2f 33 37 2e 32 32 31 2e 31 36 30 2e 35 36 2f } //00 00 
		$a_01_7 = {80 10 00 00 b8 ea eb ee ce 69 60 77 3b b4 c5 15 00 50 00 80 5d 04 00 00 b4 e0 02 80 5c 22 00 00 b5 e0 02 80 00 00 01 00 1e 00 0c 00 d1 41 42 6c 61 63 6f 6c 65 2e } //4b 4c 
	condition:
		any of ($a_*)
 
}