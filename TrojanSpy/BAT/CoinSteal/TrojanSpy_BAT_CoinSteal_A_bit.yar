
rule TrojanSpy_BAT_CoinSteal_A_bit{
	meta:
		description = "TrojanSpy:BAT/CoinSteal.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 00 79 00 74 00 65 00 63 00 6f 00 69 00 6e 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 77 00 61 00 6c 00 6c 00 65 00 74 00 } //1 bytecoinwallet.wallet
		$a_01_1 = {43 72 79 70 74 6f 53 65 72 76 69 63 65 2e 70 64 62 } //1 CryptoService.pdb
		$a_01_2 = {64 00 73 00 63 00 69 00 75 00 79 00 69 00 7a 00 68 00 69 00 75 00 75 00 63 00 2e 00 70 00 68 00 70 00 3f 00 74 00 79 00 70 00 65 00 3d 00 } //1 dsciuyizhiuuc.php?type=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}