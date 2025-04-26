
rule Trojan_Win32_Vidar_C_MTB{
	meta:
		description = "Trojan:Win32/Vidar.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 54 24 12 0f b6 51 ?? 88 54 24 13 8a 51 ?? 89 5c 24 14 83 44 24 14 ?? 89 5c 24 18 83 44 24 18 ?? 8b 4c 24 14 8a da d2 e3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Vidar_C_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f b6 19 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00 0f b6 59 01 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00 0f b6 59 02 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00 0f b6 59 03 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00 } //2
		$a_01_1 = {8b 4c 24 04 68 d4 f7 41 00 e8 e8 85 00 00 8d 73 6c 8d 7b 04 8d 4b 30 e8 5a 86 00 00 8d 4b 1c e8 52 86 00 00 8d 4b 10 e8 4a 86 00 00 89 f9 e8 43 86 00 00 89 f1 e8 3c 86 00 00 } //1
		$a_01_2 = {22 69 64 22 3a 31 2c 22 6d 65 74 68 6f 64 22 3a 22 53 74 6f 72 61 67 65 2e 67 65 74 43 6f 6f 6b 69 65 73 22 } //1 "id":1,"method":"Storage.getCookies"
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 5c 6d 6f 6e 65 72 6f 2d 63 6f 72 65 } //1 SOFTWARE\monero-project\monero-core
		$a_01_4 = {77 61 6c 6c 65 74 5f 70 61 74 68 } //1 wallet_path
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 61 72 74 69 6e 20 50 72 69 6b 72 79 6c 5c 57 69 6e 53 43 50 20 32 5c 53 65 73 73 69 6f 6e 73 } //1 Software\Martin Prikryl\WinSCP 2\Sessions
		$a_01_6 = {68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 6c 37 39 33 6f 79 } //1 https://t.me/l793oy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}