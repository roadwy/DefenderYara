
rule Trojan_Win32_CoinMiner_DD{
	meta:
		description = "Trojan:Win32/CoinMiner.DD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 63 75 72 72 65 6e 63 79 22 20 3a 20 22 6d 30 6e 33 72 30 37 22 2c } //01 00  "currency" : "m0n3r07",
		$a_01_1 = {70 72 6f 63 65 73 73 20 68 61 63 6b 65 72 } //01 00  process hacker
		$a_01_2 = {41 6e 76 69 72 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 20 46 72 65 65 } //01 00  Anvir Task Manager Free
		$a_01_3 = {41 6e 76 69 72 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 } //01 00  Anvir Task Manager
		$a_01_4 = {41 75 73 6c 6f 67 69 63 73 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 } //01 00  Auslogics Task Manager
		$a_01_5 = {46 3a 5c 63 61 6c 63 75 6c 61 74 6f 72 5c 48 61 73 68 65 72 5c 68 61 73 68 65 72 2d 6e 67 5c 62 69 6e 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 64 73 73 65 63 2e 70 64 62 } //00 00  F:\calculator\Hasher\hasher-ng\bin\Win32\Release\dssec.pdb
	condition:
		any of ($a_*)
 
}