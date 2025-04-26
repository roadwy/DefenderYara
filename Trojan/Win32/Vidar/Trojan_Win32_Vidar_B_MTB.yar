
rule Trojan_Win32_Vidar_B_MTB{
	meta:
		description = "Trojan:Win32/Vidar.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 80 34 38 5e 5f 5e 5b 8b e5 5d c3 } //1
		$a_01_1 = {2b c8 be 98 6c 14 00 8d 49 00 8a 14 01 88 10 40 4e 75 f7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Vidar_B_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {8a 19 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00 8a 59 01 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00 8a 59 02 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00 8a 59 03 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00 } //2
		$a_01_1 = {22 69 64 22 3a 31 2c 22 6d 65 74 68 6f 64 22 3a 22 53 74 6f 72 61 67 65 2e 67 65 74 43 6f 6f 6b 69 65 73 22 } //1 "id":1,"method":"Storage.getCookies"
		$a_01_2 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //1 \Monero\wallet.keys
		$a_01_3 = {5c 42 72 61 76 65 57 61 6c 6c 65 74 5c 50 72 65 66 65 72 65 6e 63 65 73 } //1 \BraveWallet\Preferences
		$a_01_4 = {2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 31 30 20 26 20 72 64 20 2f 73 20 2f 71 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //1 /c timeout /t 10 & rd /s /q "C:\ProgramData\
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 61 72 74 69 6e 20 50 72 69 6b 72 79 6c 5c 57 69 6e 53 43 50 20 32 5c 53 65 73 73 69 6f 6e 73 } //1 Software\Martin Prikryl\WinSCP 2\Sessions
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 5c 6d 6f 6e 65 72 6f 2d 63 6f 72 65 } //1 SOFTWARE\monero-project\monero-core
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}