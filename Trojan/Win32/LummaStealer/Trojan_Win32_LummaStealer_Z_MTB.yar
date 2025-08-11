
rule Trojan_Win32_LummaStealer_Z_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {31 c9 85 c0 0f 95 c1 8b 04 8d ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff e0 } //1
		$a_02_1 = {89 ca 81 ca ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 21 d1 8d 34 09 f7 d6 01 ce 21 d6 01 f0 40 31 db ff e0 } //1
		$a_02_2 = {0f b6 c0 8b 04 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff e0 } //1
		$a_00_3 = {01 c8 40 ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {34 24 8b 54 24 10 8b 0c 82 89 5c 24 0c 8b 04 9a 8b 04 87 89 7c 24 04 8b 0c 8f 0f b7 74 05 1c 0f b7 5c 0d 1c 89 f2 89 74 24 14 39 de 72 02 89 da 89 5c 24 28 8d 34 28 8d 1c 28 83 c3 2e 8d 04 32 83 c0 2e 89 44 24 08 85 d2 74 4e 01 e9 83 c1 2e ?? ?? ?? ?? ?? 0f b6 13 89 d0 04 bf 3c 1a 73 03 80 c2 20 89 d6 0f b6 01 89 c2 80 c2 bf 80 fa 1a 73 02 04 20 8b 7c 24 04 89 f2 38 c2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_3{
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
rule Trojan_Win32_LummaStealer_Z_MTB_4{
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
rule Trojan_Win32_LummaStealer_Z_MTB_5{
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
rule Trojan_Win32_LummaStealer_Z_MTB_6{
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
rule Trojan_Win32_LummaStealer_Z_MTB_7{
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
rule Trojan_Win32_LummaStealer_Z_MTB_8{
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
rule Trojan_Win32_LummaStealer_Z_MTB_9{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 74 05 83 f8 2e 75 01 } //1
		$a_01_1 = {3d 74 05 83 f9 2e 75 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_10{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 60 08 01 b3 85 d7 34 66 85 80 b5 4a a9 2b 43 09 2a d6 47 e5 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_11{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e6 09 f2 89 57 48 01 c8 89 47 44 83 f8 08 72 39 8b 74 24 08 eb 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_12{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 56 48 83 c0 f8 89 46 44 83 f8 07 76 42 8b 4e 30 3b 4e 34 73 e7 8d 41 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_13{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 77 28 73 25 56 ff 77 2c ff 77 20 ff 71 34 ff 51 30 83 c4 10 85 c0 0f 84 7c 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_14{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7a 36 14 1b 4f b1 6b 6b 91 3c f8 0c ed 40 a6 38 f9 ef 8b 67 d6 8c b2 1b af 31 c5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_15{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fd 41 80 e5 29 41 80 e2 10 45 08 ea 45 08 df 41 80 e3 29 80 e1 d6 44 08 d9 44 30 d1 41 f6 d7 41 08 cf 89 d9 20 d1 30 da 08 ca 44 89 f9 f6 d1 20 d1 f6 d2 44 20 fa 08 ca 44 08 c8 f6 d0 89 d1 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_16{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 63 52 3c 4d 03 c2 4d 8b d0 4c 89 55 b8 4c 89 45 b0 45 33 c9 66 41 81 7a 18 0b 02 41 0f 94 c1 44 89 4d ac 45 85 c9 4d 8b d8 4d 0f 45 da 4c 89 5d a0 b9 60 00 00 00 89 4d 9c bb 18 00 00 00 48 63 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_17{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 1c 38 88 1c 39 0f b6 5c 38 ff 88 5c 39 ff 0f b6 5c 38 fe 88 5c 39 fe 0f b6 5c 38 fd 88 5c 39 fd 0f b6 5c 38 fc 88 5c 39 fc 0f b6 5c 38 fb 88 5c 39 fb 0f b6 5c 38 fa 88 5c 39 fa 0f b6 5c 38 f9 88 5c 39 f9 83 c7 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_18{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 20 f3 45 88 d3 41 20 fb 41 30 fa 45 08 d3 41 88 ea 41 80 f2 ff 40 88 df 40 80 f7 ff 41 88 f6 41 80 f6 01 45 88 d7 41 80 e7 ff 44 20 f5 41 88 fc 41 80 e4 ff 44 20 f3 41 08 ef 41 08 dc 45 30 e7 41 08 fa 41 80 f2 ff 41 80 ce 01 45 20 f2 45 08 d7 45 88 da 41 80 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_19{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 30 c7 40 88 f0 34 ff 45 88 f4 41 80 f4 ff 41 88 fd 41 80 f5 00 88 c1 80 e1 00 44 20 ee 44 88 e2 80 e2 00 45 20 ee 40 08 f1 44 08 f2 30 d1 44 08 e0 34 ff 41 80 cd 00 44 20 e8 08 c1 40 88 f8 34 00 44 88 fa 80 f2 ff 40 88 fe 40 80 f6 01 41 88 c6 41 80 e6 ff 41 88 f4 41 80 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_20{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3c af c6 43 3d c1 c6 43 3e e0 c6 43 3f c7 c6 43 40 8c c6 43 41 c5 c6 43 42 ab c6 43 43 cb c6 43 44 a6 c6 43 45 c9 c6 43 46 a3 c6 43 47 cf c6 43 48 5b c6 43 49 cd c6 43 4a b0 c6 43 4b f3 c6 43 4c 9a c6 43 4d f1 c6 43 4e 61 c6 43 4f f7 c6 43 50 64 c6 43 51 f5 c6 43 52 9f c6 43 53 fb c6 43 54 65 c6 43 55 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_21{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 5c 51 3a 1d ab d9 02 2b 28 3b 82 87 c3 08 c6 2e f4 5a b9 27 fd 1e 8e 28 6f 1f f5 17 06 f3 44 2f 35 77 ca 2a 48 ef b6 05 d8 59 22 61 3e ed e6 12 8c 2b d8 77 29 90 12 ac 0f 49 1c 8b dc fd 84 e4 44 f7 08 0c 1b fb 25 5b cc 8b a6 59 d7 77 70 2f b7 1f 6e 5b a0 94 0a 72 4c 37 a5 71 24 a8 23 70 fb 9a cd 3c 1a 37 22 59 1b d8 42 0f f7 2a ca dd a6 e5 0f 8e a5 c5 a4 6c e6 ec 01 fa 0b 49 63 69 aa bd 85 f5 d8 83 5b bb 42 0e 6a 7a 0e d1 0d cc d9 94 85 7a 8a 89 7d 5f e9 b1 99 f9 41 0f 48 d8 5e 24 5c a9 } //1
		$a_01_1 = {03 87 85 a2 e9 e5 c9 b6 13 5b 6c d0 2f da 86 22 fc 0b 5e 2a e7 1d 7c 1e bb 5c 5f 29 c3 46 3e 82 a3 6c 59 78 cf 57 91 5e 8a 76 33 db b7 7c df 50 d3 80 f6 4a 63 a7 d5 bf 7c 3a 78 b8 42 8c 21 83 61 9f e2 63 66 99 6e fb 5e b2 9e ac ca 96 42 f2 19 aa 79 07 7d d4 43 34 a1 1f 73 3f 82 d3 bd c9 93 34 ca a8 19 71 e0 ca a9 06 c0 5b 9b ae bb c1 69 f4 8a 1b ed 7c d6 01 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_LummaStealer_Z_MTB_22{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7e 51 92 9b 7b 01 b1 5a b9 b5 da e8 09 a9 1a fd 78 b8 da 5d 35 72 cb 27 d2 e8 } //1
		$a_01_1 = {fc 06 93 24 ae 01 21 d2 28 2a ab 86 13 bd 37 48 f9 a8 ce 94 ff 03 b1 21 bf d3 f5 f5 54 5e c5 6e 27 20 7d 1b f9 fb 26 f4 d0 f3 02 76 57 09 83 c6 84 c0 21 ee 6b ef b8 b2 7a 02 54 75 af d8 73 0f 3f 4c c3 54 e0 ee d9 75 31 e1 ab bc 9e 45 10 0b 0c bf b8 f9 f4 f3 56 73 8e 76 2e a5 18 ba ce f8 ad 9b 0d 03 73 9b a9 e1 b3 e2 5e 7c b3 ca fd 7f 59 31 aa f3 27 06 ab 25 7d 9e 3f dc 03 7d 85 ba 9f 35 80 cd b1 7f 19 a9 39 ff 9c 3e 5b d3 41 e4 fc 65 a2 81 fd 6b d3 7d 94 1f 57 05 60 a9 b6 f1 57 09 76 2e c0 c0 57 ef b6 0a e9 21 d2 45 62 ff ae 50 3f 3d 07 49 e7 34 5f ab 9c 51 cb 1d 33 7b a1 ef bc 5b eb 14 97 42 2f 33 b4 56 ad e0 f3 17 e0 5e 6f 15 8c 54 3e 20 54 f2 ea c1 98 6d 64 } //1
		$a_01_2 = {e6 93 0f 32 8a 62 79 64 3f af 6a 4f 55 34 cf d2 aa 0a 05 a1 d2 b7 1f 29 bb 1f 1b be 5a 4a 29 f8 8e f9 46 71 74 71 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}