
rule TrojanDownloader_Win32_Spycos_P{
	meta:
		description = "TrojanDownloader:Win32/Spycos.P,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {c1 ed 11 33 dd 03 c3 03 d8 8b e8 c1 e5 09 33 c5 03 d0 03 c2 8b ea c1 ed 03 } //03 00 
		$a_01_1 = {3a 44 45 4c 42 41 54 } //01 00 
		$a_01_2 = {4d 35 53 65 31 56 53 51 43 37 43 6c 2f 32 30 39 47 4a 75 4d 76 4d 36 66 70 } //01 00 
		$a_01_3 = {34 73 78 58 76 4d 53 51 56 4f 53 6f 57 34 68 77 6b 7a 64 70 74 67 } //01 00 
		$a_01_4 = {67 56 4e 68 43 44 33 47 6e 72 59 6a 6e 41 4b 33 58 4a 53 72 46 41 } //00 00 
	condition:
		any of ($a_*)
 
}