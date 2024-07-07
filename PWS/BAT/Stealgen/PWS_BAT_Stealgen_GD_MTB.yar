
rule PWS_BAT_Stealgen_GD_MTB{
	meta:
		description = "PWS:BAT/Stealgen.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 0e 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 65 72 } //Stealer  1
		$a_80_1 = {5f 34 32 30 5f } //_420_  1
		$a_80_2 = {68 75 66 66 6d 61 6e } //huffman  1
		$a_80_3 = {4e 6f 72 64 50 61 73 73 } //NordPass  1
		$a_80_4 = {3c 47 72 61 62 3e } //<Grab>  1
		$a_80_5 = {44 42 50 61 73 73 } //DBPass  1
		$a_80_6 = {50 72 6f 74 6f 6e 56 50 4e } //ProtonVPN  1
		$a_80_7 = {42 69 74 63 6f 69 6e } //Bitcoin  1
		$a_80_8 = {45 6c 65 63 74 72 75 6d } //Electrum  1
		$a_80_9 = {4d 6f 6e 65 72 6f } //Monero  1
		$a_80_10 = {45 78 6f 64 75 73 } //Exodus  1
		$a_80_11 = {43 61 72 64 } //Card  1
		$a_80_12 = {50 61 73 73 77 6f 72 64 } //Password  1
		$a_80_13 = {4f 70 65 6e 56 50 4e } //OpenVPN  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=10
 
}
rule PWS_BAT_Stealgen_GD_MTB_2{
	meta:
		description = "PWS:BAT/Stealgen.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0b 00 00 "
		
	strings :
		$a_80_0 = {43 72 65 64 69 74 43 61 72 64 } //CreditCard  10
		$a_80_1 = {41 75 74 6f 66 69 6c 6c } //Autofill  1
		$a_80_2 = {57 61 6c 6c 65 74 50 61 72 73 65 72 } //WalletParser  1
		$a_80_3 = {45 6c 65 63 74 72 75 6d } //Electrum  1
		$a_80_4 = {43 6f 6c 64 57 61 6c 6c 65 74 73 } //ColdWallets  1
		$a_80_5 = {45 74 68 65 72 65 75 6d } //Ethereum  1
		$a_80_6 = {45 78 6f 64 75 73 } //Exodus  1
		$a_80_7 = {4d 6f 6e 65 72 6f } //Monero  1
		$a_80_8 = {53 71 6c 69 74 65 } //Sqlite  1
		$a_80_9 = {43 4f 4f 4c 5f 42 49 54 54 59 5f 4b 49 54 54 59 } //COOL_BITTY_KITTY  1
		$a_80_10 = {47 6c 6f 72 79 5f 74 6f 5f 74 68 65 5f 47 72 65 61 74 5f 4c 65 6e 69 6e } //Glory_to_the_Great_Lenin  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=19
 
}