
rule Trojan_Win32_Vidar_RPX_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 36 35 36 31 31 39 39 36 35 38 38 31 37 37 31 35 } //01 00  76561199658817715
		$a_01_1 = {73 61 39 6f 6b } //01 00  sa9ok
		$a_01_2 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //01 00  passwords.txt
		$a_01_3 = {42 72 61 76 65 57 61 6c 6c 65 74 } //01 00  BraveWallet
		$a_01_4 = {46 69 6c 65 5a 69 6c 6c 61 } //01 00  FileZilla
		$a_01_5 = {72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //01 00  recentservers.xml
		$a_01_6 = {40 77 61 6c 6c 65 74 5f 70 61 74 68 } //01 00  @wallet_path
		$a_01_7 = {4d 6f 6e 65 72 6f } //01 00  Monero
		$a_01_8 = {77 61 6c 6c 65 74 2e 6b 65 79 73 } //01 00  wallet.keys
		$a_01_9 = {61 00 76 00 67 00 68 00 6f 00 6f 00 6b 00 78 00 2e 00 64 00 6c 00 6c 00 } //00 00  avghookx.dll
	condition:
		any of ($a_*)
 
}