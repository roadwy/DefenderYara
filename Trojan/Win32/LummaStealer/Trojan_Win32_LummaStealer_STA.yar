
rule Trojan_Win32_LummaStealer_STA{
	meta:
		description = "Trojan:Win32/LummaStealer.STA,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0b 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //10
		$a_01_1 = {22 76 22 3a 20 22 50 61 73 73 77 6f 72 64 22 2c } //1 "v": "Password",
		$a_01_2 = {22 65 7a 22 3a 20 22 52 6f 6e 69 6e 20 57 61 6c 6c 65 74 22 } //1 "ez": "Ronin Wallet"
		$a_01_3 = {22 65 7a 22 3a 20 22 42 69 6e 61 6e 63 65 20 43 68 61 69 6e 20 57 61 6c 6c 65 74 22 } //1 "ez": "Binance Chain Wallet"
		$a_01_4 = {22 70 22 3a 20 22 25 61 70 70 64 61 74 61 25 5c 5c 45 74 68 65 72 65 75 6d 22 2c } //1 "p": "%appdata%\\Ethereum",
		$a_01_5 = {22 70 22 3a 20 22 25 61 70 70 64 61 74 61 25 5c 5c 42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 73 22 2c } //1 "p": "%appdata%\\Bitcoin\wallets",
		$a_01_6 = {22 70 22 3a 20 22 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 5c 4d 69 63 72 6f 73 6f 66 74 5c 5c 45 64 67 65 5c 5c 55 73 65 72 20 44 61 74 61 22 2c } //1 "p": "%localappdata%\\Microsoft\\Edge\\User Data",
		$a_01_7 = {22 7a 22 3a 20 22 57 61 6c 6c 65 74 73 2f 42 69 74 63 6f 69 6e 20 63 6f 72 65 22 2c } //1 "z": "Wallets/Bitcoin core",
		$a_01_8 = {22 7a 22 3a 20 22 57 61 6c 6c 65 74 73 2f 44 61 73 68 43 6f 72 65 22 2c } //1 "z": "Wallets/DashCore",
		$a_01_9 = {22 6e 22 3a 20 22 63 68 72 6f 6d 65 2e 65 78 65 22 2c } //1 "n": "chrome.exe",
		$a_01_10 = {22 65 6e 22 3a 20 22 65 6a 62 61 6c 62 61 6b 6f 70 6c 63 68 6c 67 68 65 63 64 61 6c 6d 65 65 65 61 6a 6e 69 6d 68 6d 22 2c } //1 "en": "ejbalbakoplchlghecdalmeeeajnimhm",
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=16
 
}