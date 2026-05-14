
rule Trojan_MacOS_FakeWallet_AMTB{
	meta:
		description = "Trojan:MacOS/FakeWallet!AMTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {35 31 39 30 65 66 31 37 33 33 31 38 33 61 30 64 63 36 33 66 62 36 32 33 33 35 37 66 35 36 64 36 } //5190ef1733183a0dc63fb623357f56d6  2
		$a_80_1 = {51 75 69 74 20 54 72 65 7a 6f 72 20 53 75 69 74 65 } //Quit Trezor Suite  1
		$a_80_2 = {48 69 64 65 20 54 72 65 7a 6f 72 20 53 75 69 74 65 } //Hide Trezor Suite  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}