
rule Trojan_Win32_CoinMiner_AV_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.AV!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {45 6c 65 63 74 72 75 6d 5c 65 6c 65 63 74 72 75 6d 2e 64 61 74 } //Electrum\electrum.dat  02 00 
		$a_80_1 = {6d 75 6c 74 69 62 69 74 2e 77 61 6c 6c 65 74 } //multibit.wallet  02 00 
		$a_80_2 = {42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } //Bitcoin\wallet.dat  03 00 
		$a_80_3 = {57 61 6c 6c 65 74 20 53 74 65 61 6c 65 72 5c 42 57 53 2d 53 74 75 62 5c 52 65 6c 65 61 73 65 5c 42 57 53 2d 53 74 75 62 2e 70 64 62 } //Wallet Stealer\BWS-Stub\Release\BWS-Stub.pdb  00 00 
		$a_00_4 = {5d 04 00 00 } //0e 6e 
	condition:
		any of ($a_*)
 
}