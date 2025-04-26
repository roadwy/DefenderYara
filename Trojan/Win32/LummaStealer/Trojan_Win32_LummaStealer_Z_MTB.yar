
rule Trojan_Win32_LummaStealer_Z_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {57 61 6c 6c 65 74 73 2f 45 6c 65 63 74 72 75 6d } //1 Wallets/Electrum
		$a_81_1 = {57 61 6c 6c 65 74 73 2f 45 6c 65 63 74 72 6f 6e 43 61 73 68 } //1 Wallets/ElectronCash
		$a_81_2 = {25 61 70 70 64 61 74 61 25 5c 63 6f 6d 2e 6c 69 62 65 72 74 79 2e 6a 61 78 78 5c 49 6e 64 65 78 65 64 44 42 } //1 %appdata%\com.liberty.jaxx\IndexedDB
		$a_81_3 = {45 78 6f 64 75 73 57 65 62 33 } //1 ExodusWeb3
		$a_81_4 = {77 61 6c 6c 65 74 73 2f 45 74 68 65 72 65 75 6d } //1 wallets/Ethereum
		$a_81_5 = {25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 43 6f 69 6e 6f 6d 69 } //1 %localappdata%\Coinomi
		$a_81_6 = {6b 65 79 73 74 6f 72 65 } //1 keystore
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {6c 69 64 3d 25 73 26 6a 3d 25 73 26 76 65 72 3d 34 2e 30 } //1 lid=%s&j=%s&ver=4.0
		$a_81_1 = {54 65 73 6c 61 42 72 6f 77 73 65 72 2f 35 2e 35 } //1 TeslaBrowser/5.5
		$a_81_2 = {53 63 72 65 65 6e 2e 70 6e 67 } //1 Screen.png
		$a_81_3 = {53 63 72 65 65 6e 20 52 65 73 6f 6c 75 74 6f 6e 3a } //1 Screen Resoluton:
		$a_81_4 = {55 73 65 72 3a } //1 User:
		$a_81_5 = {44 6f 6d 61 69 6e 3a } //1 Domain:
		$a_81_6 = {57 6f 72 6b 67 72 6f 75 70 3a } //1 Workgroup:
		$a_81_7 = {50 68 79 73 69 63 61 6c 20 49 6e 73 74 61 6c 6c 65 64 20 4d 65 6d 6f 72 79 3a } //1 Physical Installed Memory:
		$a_81_8 = {50 4f 53 54 20 2f 61 70 69 20 48 54 54 50 2f 31 2e 31 } //1 POST /api HTTP/1.1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_3{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {25 61 70 70 64 61 74 61 25 5c 63 6f 6d 2e 6c 69 62 65 72 74 79 2e 6a 61 78 78 } //1 %appdata%\com.liberty.jaxx
		$a_81_1 = {62 69 74 63 6f 69 6e } //1 bitcoin
		$a_81_2 = {62 69 6e 61 6e 63 65 } //1 binance
		$a_81_3 = {4d 61 69 6c 20 43 6c 69 65 6e 74 73 2f 54 68 65 42 61 74 } //1 Mail Clients/TheBat
		$a_81_4 = {4d 61 69 6c 20 43 6c 69 65 6e 74 73 2f 50 65 67 61 73 75 73 } //1 Mail Clients/Pegasus
		$a_81_5 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 54 65 6c 65 67 72 61 6d } //1 Applications/Telegram
		$a_81_6 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 31 50 61 73 73 77 6f 72 64 } //1 Applications/1Password
		$a_81_7 = {57 61 6c 6c 65 74 73 2f 44 61 65 64 61 6c 75 73 } //1 Wallets/Daedalus
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_4{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 64 61 74 61 5c 65 78 6f 64 75 73 } //1 appdata\exodus
		$a_01_1 = {61 70 70 64 61 74 61 5c 62 69 6e 61 6e 63 65 } //1 appdata\binance
		$a_02_2 = {68 00 74 00 74 00 70 00 [0-50] 24 00 65 00 6e 00 76 00 3a 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 [0-50] 24 00 65 00 6e 00 76 00 3a 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //1
		$a_01_3 = {6b 65 65 76 6f 2d 77 61 6c 6c 65 74 90 } //1
		$a_01_4 = {65 6c 65 63 74 72 75 6d } //1 electrum
		$a_01_5 = {6f 6e 65 6b 65 79 2d 77 61 6c 6c 65 74 } //1 onekey-wallet
		$a_01_6 = {65 6e 76 3a 61 70 70 64 61 74 61 } //1 env:appdata
		$a_01_7 = {67 65 74 2d 77 6d 69 6f 62 6a 65 63 74 2d 63 6c 61 73 73 77 69 6e 33 32 5f 63 6f 6d 70 75 74 65 72 73 79 73 74 65 6d } //1 get-wmiobject-classwin32_computersystem
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_5{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {77 65 62 65 78 74 65 6e 73 69 6f 6e 40 6d 65 74 61 6d 61 73 6b 2e 69 6f } //1 webextension@metamask.io
		$a_81_1 = {45 6c 65 63 74 72 75 6d 5c 77 61 6c 6c 65 74 73 } //1 Electrum\wallets
		$a_81_2 = {42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 73 } //1 Bitcoin\wallets
		$a_81_3 = {4d 65 74 61 4d 61 73 6b } //1 MetaMask
		$a_81_4 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_81_5 = {57 61 6c 6c 65 74 73 2f 44 61 73 68 43 6f 72 65 } //1 Wallets/DashCore
		$a_81_6 = {52 6f 6e 69 6e 20 57 61 6c 6c 65 74 } //1 Ronin Wallet
		$a_81_7 = {4c 65 61 70 20 57 61 6c 6c 65 74 } //1 Leap Wallet
		$a_81_8 = {41 67 72 65 6e 74 } //1 Agrent
		$a_81_9 = {6c 6f 63 61 6c 68 6f 73 74 } //1 localhost
		$a_81_10 = {70 61 72 61 6d 73 } //1 params
		$a_81_11 = {65 78 6f 64 75 73 } //1 exodus
		$a_81_12 = {57 61 6c 6c 65 74 73 2f 4a 41 58 58 } //1 Wallets/JAXX
		$a_81_13 = {6b 65 79 73 74 6f 72 65 } //1 keystore
		$a_81_14 = {57 61 6c 6c 65 74 73 2f 42 69 6e 61 6e 63 65 } //1 Wallets/Binance
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_6{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 15 00 00 "
		
	strings :
		$a_81_0 = {45 6c 65 63 74 72 75 6d } //1 Electrum
		$a_81_1 = {45 6c 65 63 74 72 6f 6e 43 61 73 68 } //1 ElectronCash
		$a_81_2 = {45 78 6f 64 75 73 } //1 Exodus
		$a_81_3 = {45 74 68 65 72 65 75 6d } //1 Ethereum
		$a_81_4 = {42 69 74 43 6f 69 6e } //1 BitCoin
		$a_81_5 = {42 69 6e 61 6e 63 65 } //1 Binance
		$a_81_6 = {78 76 65 72 73 65 } //1 xverse
		$a_81_7 = {64 61 65 64 61 6c 75 73 20 } //1 daedalus 
		$a_81_8 = {6c 65 61 70 } //1 leap
		$a_81_9 = {47 6c 61 73 73 } //1 Glass
		$a_81_10 = {52 6f 6e 69 6e } //1 Ronin
		$a_81_11 = {46 6f 72 6e 69 74 65 72 } //1 Forniter
		$a_81_12 = {52 41 42 42 59 } //1 RABBY
		$a_81_13 = {43 6f 69 6e 6f 6d 69 } //1 Coinomi
		$a_81_14 = {6b 65 79 73 74 6f 72 65 } //10 keystore
		$a_81_15 = {4a 41 58 58 } //10 JAXX
		$a_81_16 = {62 61 73 65 36 34 65 6e 63 6f 64 65 } //10 base64encode
		$a_81_17 = {64 65 63 6f 64 65 62 61 73 65 36 34 } //10 decodebase64
		$a_00_18 = {66 69 6e 64 69 6e 67 20 63 65 6e 74 72 61 6c 20 64 69 72 65 63 74 6f 72 79 00 } //10
		$a_00_19 = {70 61 73 73 77 6f 72 64 } //10 password
		$a_00_20 = {75 73 65 72 2d 61 67 65 6e 74 } //10 user-agent
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*10+(#a_81_15  & 1)*10+(#a_81_16  & 1)*10+(#a_81_17  & 1)*10+(#a_00_18  & 1)*10+(#a_00_19  & 1)*10+(#a_00_20  & 1)*10) >=74
 
}