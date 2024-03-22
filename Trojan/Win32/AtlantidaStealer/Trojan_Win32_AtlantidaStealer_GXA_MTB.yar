
rule Trojan_Win32_AtlantidaStealer_GXA_MTB{
	meta:
		description = "Trojan:Win32/AtlantidaStealer.GXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {42 72 6f 77 73 65 72 73 5c 42 72 6f 77 65 73 65 72 49 6e 66 6f 2e 74 78 74 } //Browsers\BroweserInfo.txt  01 00 
		$a_80_1 = {50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //Passwords.txt  01 00 
		$a_01_2 = {45 74 68 65 72 65 75 6d 5c 6b 65 79 73 74 6f 72 65 } //01 00  Ethereum\keystore
		$a_01_3 = {41 74 6c 61 6e 74 69 64 61 53 74 65 61 6c 65 72 } //01 00  AtlantidaStealer
		$a_01_4 = {45 78 6f 64 75 73 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //01 00  Exodus\Local Storage\leveldb
		$a_01_5 = {5c 42 69 6e 61 6e 63 65 5c 2a 2e 6a 73 6f 6e } //01 00  \Binance\*.json
		$a_01_6 = {42 69 6e 61 6e 63 65 57 61 6c 6c 65 74 } //01 00  BinanceWallet
		$a_01_7 = {43 79 61 6e 6f 57 61 6c 6c 65 74 } //00 00  CyanoWallet
	condition:
		any of ($a_*)
 
}