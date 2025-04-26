
rule Trojan_Win32_Vidar_A_MTB{
	meta:
		description = "Trojan:Win32/Vidar.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 43 00 4f 00 59 00 53 00 2f 00 2f 00 2f 00 68 00 64 00 72 00 } //1 CCOYS///hdr
		$a_01_1 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //1 wallet.dat
		$a_01_2 = {6d 00 6f 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 } //1 mozzzzzzzzzzz
		$a_03_3 = {40 8a 0c 85 ?? ?? ?? ?? 8b 45 08 32 0c 03 a1 ?? ?? ?? ?? 88 0c 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Vidar_A_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_03_0 = {50 57 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? 89 c7 89 f1 ?? ?? ?? ?? ?? e0 4e b7 8b 35 dc b5 41 00 50 ?? ?? 01 0e 04 eb ?? ?? ff b3 84 00 00 00 50 ?? ?? ?? ?? ?? e0 4e b7 83 c4 08 89 c7 50 ?? ?? 85 c0 } //2
		$a_01_1 = {22 69 64 22 3a 31 2c 22 6d 65 74 68 6f 64 22 3a 22 53 74 6f 72 61 67 65 2e 67 65 74 43 6f 6f 6b 69 65 73 22 } //1 "id":1,"method":"Storage.getCookies"
		$a_01_2 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //2 \Monero\wallet.keys
		$a_01_3 = {5c 42 72 61 76 65 57 61 6c 6c 65 74 5c 50 72 65 66 65 72 65 6e 63 65 73 } //2 \BraveWallet\Preferences
		$a_01_4 = {2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 31 30 20 26 20 72 64 20 2f 73 20 2f 71 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //1 /c timeout /t 10 & rd /s /q "C:\ProgramData\
		$a_01_5 = {77 61 6c 6c 65 74 5f 70 61 74 68 } //1 wallet_path
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 5c 6d 6f 6e 65 72 6f 2d 63 6f 72 65 } //1 SOFTWARE\monero-project\monero-core
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}