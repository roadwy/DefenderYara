
rule Trojan_Win64_Tedy_LMP_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,69 00 69 00 0e 00 00 "
		
	strings :
		$a_81_0 = {43 20 41 20 53 75 69 20 77 61 6c 6c 65 74 } //1 C A Sui wallet
		$a_81_1 = {42 72 61 61 76 6f 73 3a 20 42 69 74 63 6f 69 6e } //2 Braavos: Bitcoin
		$a_81_2 = {43 6f 69 6e 62 61 73 65 20 57 61 6c 6c 65 74 20 65 78 74 65 6e 73 69 6f 6e } //3 Coinbase Wallet extension
		$a_81_3 = {4c 65 61 70 20 57 61 6c 6c 65 74 } //4 Leap Wallet
		$a_81_4 = {43 6f 6d 70 61 73 73 20 57 61 6c 6c 65 74 20 66 6f 72 20 53 65 69 } //5 Compass Wallet for Sei
		$a_81_5 = {46 72 61 63 74 61 6c 20 57 61 6c 6c 65 74 } //6 Fractal Wallet
		$a_81_6 = {53 74 61 74 69 6f 6e 20 57 61 6c 6c 65 74 } //7 Station Wallet
		$a_81_7 = {44 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 6f 6e 65 72 6f 20 47 55 49 20 57 61 6c 6c 65 74 } //8 D:\Program Files\Monero GUI Wallet
		$a_81_8 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 6f 6e 65 72 6f 20 47 55 49 20 57 61 6c 6c 65 74 } //9 C:\Program Files\Monero GUI Wallet
		$a_81_9 = {5d 20 33 36 30 20 53 61 6e 64 62 6f 78 20 64 65 74 65 63 74 65 64 } //10 ] 360 Sandbox detected
		$a_81_10 = {5b 2b 5d 20 43 6c 69 70 62 6f 61 72 64 20 63 6f 6e 74 65 6e 74 20 73 65 74 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //11 [+] Clipboard content set successfully.
		$a_81_11 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 63 6c 69 70 62 6f 61 72 64 20 63 6f 6e 74 65 6e 74 2e } //12 [-] Failed to set clipboard content.
		$a_81_12 = {5b 2b 5d 20 52 75 6e 53 68 65 6c 6c 63 6f 64 65 } //13 [+] RunShellcode
		$a_81_13 = {5b 2b 5d 20 4d 61 69 6e 6c 6f 6f 70 43 6f 6d 6d 61 6e 64 5f 42 6c 75 65 53 63 72 65 65 6e } //14 [+] MainloopCommand_BlueScreen
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8+(#a_81_8  & 1)*9+(#a_81_9  & 1)*10+(#a_81_10  & 1)*11+(#a_81_11  & 1)*12+(#a_81_12  & 1)*13+(#a_81_13  & 1)*14) >=105
 
}