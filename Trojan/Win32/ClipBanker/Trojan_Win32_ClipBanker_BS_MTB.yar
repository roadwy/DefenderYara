
rule Trojan_Win32_ClipBanker_BS_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 5b 31 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 35 2c 33 34 7d 29 } //2 ([13][a-km-zA-HJ-NP-Z1-9]{25,34})
		$a_01_1 = {6e 6f 77 20 74 68 65 20 70 72 6f 67 72 61 6d 20 69 73 20 6d 6f 6e 69 74 6f 72 69 6e 67 20 63 6c 69 70 62 6f 61 72 64 } //2 now the program is monitoring clipboard
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}