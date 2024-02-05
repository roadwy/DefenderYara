
rule PWS_BAT_Polazert_GA_MTB{
	meta:
		description = "PWS:BAT/Polazert.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f } //http://  01 00 
		$a_80_1 = {57 61 6c 6c 65 74 } //Wallet  01 00 
		$a_80_2 = {45 6c 65 63 74 72 75 6d } //Electrum  01 00 
		$a_80_3 = {45 74 68 65 72 65 75 6d } //Ethereum  01 00 
		$a_80_4 = {45 78 6f 64 75 73 } //Exodus  01 00 
		$a_80_5 = {4f 70 65 6e 56 50 4e } //OpenVPN  01 00 
		$a_80_6 = {2a 2e 72 64 70 } //*.rdp  01 00 
		$a_80_7 = {5c 64 65 66 61 75 6c 74 2e 72 64 70 } //\default.rdp  01 00 
		$a_80_8 = {6f 73 5f 63 72 79 70 74 } //os_crypt  01 00 
		$a_80_9 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //encrypted_key  01 00 
		$a_80_10 = {66 6f 72 6d 68 69 73 74 6f 72 79 2e 73 71 6c 69 74 65 } //formhistory.sqlite  01 00 
		$a_80_11 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //logins.json  00 00 
	condition:
		any of ($a_*)
 
}