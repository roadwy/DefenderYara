
rule Trojan_Win32_StellarStealer_GZK_MTB{
	meta:
		description = "Trojan:Win32/StellarStealer.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {45 74 68 65 72 65 75 6d 5c 6b 65 79 73 74 6f 72 65 } //1 Ethereum\keystore
		$a_01_1 = {44 61 74 61 5c 41 72 6d 6f 72 79 } //1 Data\Armory
		$a_01_2 = {5c 46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //1 \FileZilla\recentservers.xml
		$a_01_3 = {5c 77 61 6c 6c 65 74 2e 64 61 74 } //1 \wallet.dat
		$a_01_4 = {57 61 6c 6c 65 74 73 5c 41 74 6f 6d 69 63 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Wallets\Atomic\Local Storage\leveldb
		$a_01_5 = {57 61 6c 6c 65 74 73 5c 45 74 68 65 72 65 75 6d } //1 Wallets\Ethereum
		$a_01_6 = {5c 53 4f 46 54 57 41 52 45 5c 42 69 74 63 6f 69 6e 5c 42 69 74 63 6f 69 6e 2d 51 74 } //1 \SOFTWARE\Bitcoin\Bitcoin-Qt
		$a_01_7 = {57 61 6c 6c 65 74 73 5c 5a 63 61 73 68 } //1 Wallets\Zcash
		$a_01_8 = {5c 54 45 4d 50 5c 42 4f 46 55 50 4d 4a 57 55 53 46 56 53 4e 49 42 44 4a 45 45 } //1 \TEMP\BOFUPMJWUSFVSNIBDJEE
		$a_01_9 = {57 61 6c 6c 65 74 73 5c 42 79 74 65 63 6f 69 6e } //1 Wallets\Bytecoin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}