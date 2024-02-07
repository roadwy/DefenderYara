
rule TrojanSpy_Win32_TinyNuke_A_MTB{
	meta:
		description = "TrojanSpy:Win32/TinyNuke.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 12 00 00 05 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 69 7a 75 77 36 72 63 6c 62 67 6c 32 6c 77 73 68 2e 6f 6e 69 6f 6e 2f 6f 2e 70 68 70 } //02 00  http://izuw6rclbgl2lwsh.onion/o.php
		$a_81_1 = {62 61 6e 6e 65 64 5f 74 6f 72 5f 6e 6f 64 65 73 } //02 00  banned_tor_nodes
		$a_81_2 = {65 6c 65 63 74 72 75 6d 5f 64 61 74 61 5c 77 61 6c 6c 65 74 73 5c } //02 00  electrum_data\wallets\
		$a_81_3 = {4b 65 79 6c 6f 67 } //01 00  Keylog
		$a_81_4 = {78 36 34 20 68 6f 6f 6b 73 20 63 6c 65 61 72 65 64 } //01 00  x64 hooks cleared
		$a_81_5 = {78 33 32 20 68 6f 6f 6b 73 20 63 6c 65 61 72 65 64 } //01 00  x32 hooks cleared
		$a_81_6 = {73 76 63 68 6f 73 74 2e 65 78 65 } //02 00  svchost.exe
		$a_81_7 = {69 6e 6a 65 63 74 73 } //01 00  injects
		$a_81_8 = {5c 5c 2e 5c 70 69 70 65 5c 25 78 } //01 00  \\.\pipe\%x
		$a_81_9 = {51 6b 6b 62 61 6c } //02 00  Qkkbal
		$a_81_10 = {25 41 50 50 44 41 54 41 25 5c 42 69 74 63 6f 69 6e 5c } //02 00  %APPDATA%\Bitcoin\
		$a_81_11 = {25 41 50 50 44 41 54 41 25 5c 57 61 6c 6c 65 74 57 61 73 61 62 69 5c 43 6c 69 65 6e 74 5c 57 61 6c 6c 65 74 73 5c } //02 00  %APPDATA%\WalletWasabi\Client\Wallets\
		$a_81_12 = {25 41 50 50 44 41 54 41 25 5c 45 6c 65 63 74 72 75 6d 5c 77 61 6c 6c 65 74 73 5c } //02 00  %APPDATA%\Electrum\wallets\
		$a_81_13 = {77 61 6c 6c 65 74 2e 64 61 74 } //01 00  wallet.dat
		$a_81_14 = {45 6e 63 72 79 70 74 20 57 61 6c 6c 65 74 } //01 00  Encrypt Wallet
		$a_81_15 = {55 6e 6c 6f 63 6b 20 57 61 6c 6c 65 74 } //01 00  Unlock Wallet
		$a_81_16 = {44 65 63 72 79 70 74 20 57 61 6c 6c 65 74 } //01 00  Decrypt Wallet
		$a_81_17 = {69 6e 6a 41 72 63 68 39 36 7a 2e 65 78 65 } //00 00  injArch96z.exe
		$a_00_18 = {5d 04 00 00 0e 4b 04 80 5c 2a 00 00 0f 4b 04 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}