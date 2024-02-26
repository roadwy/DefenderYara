
rule Trojan_Win32_LummaStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 d3 56 56 80 ea 13 46 d0 ca 46 f6 d2 f7 d6 fe c2 56 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_LummaStealer_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 b0 6a 40 68 00 30 00 00 8b 4d e4 8b 51 50 52 6a 00 8b 45 cc 50 ff 55 b0 89 45 ec 83 7d ec 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_LummaStealer_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/LummaStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 73 5f 63 72 79 70 74 2e 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00  os_crypt.encrypted_key
		$a_01_1 = {52 00 6f 00 6e 00 69 00 6e 00 20 00 57 00 61 00 6c 00 6c 00 65 00 74 00 } //01 00  Ronin Wallet
		$a_01_2 = {42 00 69 00 6e 00 61 00 6e 00 63 00 65 00 20 00 43 00 68 00 61 00 69 00 6e 00 20 00 57 00 61 00 6c 00 6c 00 65 00 74 00 } //01 00  Binance Chain Wallet
		$a_01_3 = {43 00 6f 00 69 00 6e 00 62 00 61 00 73 00 65 00 } //01 00  Coinbase
		$a_01_4 = {45 00 6e 00 4b 00 72 00 79 00 70 00 74 00 } //01 00  EnKrypt
		$a_01_5 = {54 00 65 00 72 00 72 00 61 00 20 00 53 00 74 00 61 00 74 00 69 00 6f 00 6e 00 } //01 00  Terra Station
		$a_01_6 = {42 00 69 00 74 00 43 00 6c 00 69 00 70 00 } //01 00  BitClip
		$a_01_7 = {53 00 74 00 65 00 65 00 6d 00 20 00 4b 00 65 00 79 00 63 00 68 00 61 00 69 00 6e 00 } //01 00  Steem Keychain
		$a_01_8 = {48 00 79 00 63 00 6f 00 6e 00 20 00 4c 00 69 00 74 00 65 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //01 00  Hycon Lite Client
		$a_01_9 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //01 00  Network\Cookies
		$a_01_10 = {64 00 70 00 2e 00 74 00 78 00 74 00 } //01 00  dp.txt
		$a_01_11 = {34 00 35 00 2e 00 39 00 2e 00 37 00 34 00 2e 00 37 00 38 00 } //00 00  45.9.74.78
	condition:
		any of ($a_*)
 
}