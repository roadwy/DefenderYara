
rule TrojanSpy_Win32_TinyNuke_A_MTB{
	meta:
		description = "TrojanSpy:Win32/TinyNuke.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 12 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 69 7a 75 77 36 72 63 6c 62 67 6c 32 6c 77 73 68 2e 6f 6e 69 6f 6e 2f 6f 2e 70 68 70 } //5 http://izuw6rclbgl2lwsh.onion/o.php
		$a_81_1 = {62 61 6e 6e 65 64 5f 74 6f 72 5f 6e 6f 64 65 73 } //2 banned_tor_nodes
		$a_81_2 = {65 6c 65 63 74 72 75 6d 5f 64 61 74 61 5c 77 61 6c 6c 65 74 73 5c } //2 electrum_data\wallets\
		$a_81_3 = {4b 65 79 6c 6f 67 } //2 Keylog
		$a_81_4 = {78 36 34 20 68 6f 6f 6b 73 20 63 6c 65 61 72 65 64 } //1 x64 hooks cleared
		$a_81_5 = {78 33 32 20 68 6f 6f 6b 73 20 63 6c 65 61 72 65 64 } //1 x32 hooks cleared
		$a_81_6 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_81_7 = {69 6e 6a 65 63 74 73 } //2 injects
		$a_81_8 = {5c 5c 2e 5c 70 69 70 65 5c 25 78 } //1 \\.\pipe\%x
		$a_81_9 = {51 6b 6b 62 61 6c } //1 Qkkbal
		$a_81_10 = {25 41 50 50 44 41 54 41 25 5c 42 69 74 63 6f 69 6e 5c } //2 %APPDATA%\Bitcoin\
		$a_81_11 = {25 41 50 50 44 41 54 41 25 5c 57 61 6c 6c 65 74 57 61 73 61 62 69 5c 43 6c 69 65 6e 74 5c 57 61 6c 6c 65 74 73 5c } //2 %APPDATA%\WalletWasabi\Client\Wallets\
		$a_81_12 = {25 41 50 50 44 41 54 41 25 5c 45 6c 65 63 74 72 75 6d 5c 77 61 6c 6c 65 74 73 5c } //2 %APPDATA%\Electrum\wallets\
		$a_81_13 = {77 61 6c 6c 65 74 2e 64 61 74 } //2 wallet.dat
		$a_81_14 = {45 6e 63 72 79 70 74 20 57 61 6c 6c 65 74 } //1 Encrypt Wallet
		$a_81_15 = {55 6e 6c 6f 63 6b 20 57 61 6c 6c 65 74 } //1 Unlock Wallet
		$a_81_16 = {44 65 63 72 79 70 74 20 57 61 6c 6c 65 74 } //1 Decrypt Wallet
		$a_81_17 = {69 6e 6a 41 72 63 68 39 36 7a 2e 65 78 65 } //1 injArch96z.exe
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*2+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*2+(#a_81_11  & 1)*2+(#a_81_12  & 1)*2+(#a_81_13  & 1)*2+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1) >=26
 
}