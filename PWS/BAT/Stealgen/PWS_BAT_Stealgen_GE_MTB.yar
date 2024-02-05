
rule PWS_BAT_Stealgen_GE_MTB{
	meta:
		description = "PWS:BAT/Stealgen.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 12 00 0b 00 00 0a 00 "
		
	strings :
		$a_80_0 = {43 72 65 64 69 74 43 61 72 64 } //CreditCard  01 00 
		$a_80_1 = {41 75 74 6f 66 69 6c 6c } //Autofill  01 00 
		$a_80_2 = {57 61 6c 6c 65 74 50 61 72 73 65 72 } //WalletParser  01 00 
		$a_80_3 = {45 6c 65 63 74 72 75 6d } //Electrum  01 00 
		$a_80_4 = {43 6f 6c 64 57 61 6c 6c 65 74 73 } //ColdWallets  01 00 
		$a_80_5 = {45 74 68 65 72 65 75 6d } //Ethereum  01 00 
		$a_80_6 = {45 78 6f 64 75 73 } //Exodus  01 00 
		$a_80_7 = {4d 6f 6e 65 72 6f } //Monero  01 00 
		$a_80_8 = {53 71 6c 69 74 65 } //Sqlite  01 00 
		$a_80_9 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  01 00 
		$a_80_10 = {45 73 68 65 6c 6f 6e 20 52 65 76 6f 6c 75 74 69 6f 6e 20 50 72 6f 74 65 63 74 6f 72 } //Eshelon Revolution Protector  00 00 
	condition:
		any of ($a_*)
 
}