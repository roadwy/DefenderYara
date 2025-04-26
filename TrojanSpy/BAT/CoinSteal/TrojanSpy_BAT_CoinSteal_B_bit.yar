
rule TrojanSpy_BAT_CoinSteal_B_bit{
	meta:
		description = "TrojanSpy:BAT/CoinSteal.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 69 63 74 69 6d 4c 6f 67 73 } //1 VictimLogs
		$a_01_1 = {42 69 74 63 6f 69 6e 57 61 6c 6c 65 74 } //1 BitcoinWallet
		$a_01_2 = {53 65 6e 64 55 72 6c 41 6e 64 45 78 65 63 75 74 65 } //1 SendUrlAndExecute
		$a_01_3 = {67 65 74 5f 53 63 72 65 65 6e 73 68 6f 74 } //1 get_Screenshot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}