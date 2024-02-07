
rule Backdoor_Win32_Poison_G{
	meta:
		description = "Backdoor:Win32/Poison.G,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {e8 1b 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 5a 8d bd 34 fb ff ff } //01 00 
		$a_01_1 = {c5 08 00 00 ff 96 89 00 00 00 3d b7 00 00 00 75 04 c9 c2 04 00 56 8d 86 6b 09 00 00 50 8d 86 45 01 00 00 50 ff 96 fd 00 00 00 e8 07 00 00 00 77 73 32 5f 33 32 00 58 50 ff 96 9d 00 00 00 89 86 c3 0a 00 00 e8 3a 00 00 00 e1 60 b4 8e 01 00 d1 41 29 7c 15 00 1e bb ec 65 19 00 0c 58 ed ea 1d } //01 00 
		$a_03_2 = {bd 30 fa ff ff 63 6b 73 3d 75 13 c7 85 30 fa ff ff 74 74 90 01 01 3d c6 86 ef 0a 00 00 02 eb 11 c7 85 30 fa ff ff 63 6b 73 3d c6 86 ef 0a 00 00 01 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Poison_G_2{
	meta:
		description = "Backdoor:Win32/Poison.G,SIGNATURE_TYPE_PEHSTR,15 00 14 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8d 05 64 02 40 00 83 c0 04 ff d0 6a 00 e8 00 00 00 00 ff 25 f8 01 40 00 } //0a 00 
		$a_01_1 = {e8 41 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 59 8d 45 d8 50 6a 01 6a 00 51 68 01 00 00 80 ff 56 35 e8 08 00 00 00 41 70 70 44 61 74 61 } //01 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 56 } //01 00  SOFTWARE\Classes\http\shell\open\commandV
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}