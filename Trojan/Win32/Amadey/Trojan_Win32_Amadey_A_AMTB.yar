
rule Trojan_Win32_Amadey_A_AMTB{
	meta:
		description = "Trojan:Win32/Amadey.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_80_0 = {8b 15 88 1f 42 00 c1 e2 0d 33 15 88 1f 42 00 89 15 88 1f 42 00 a1 88 1f 42 00 c1 e8 11 33 05 88 1f 42 00 a3 88 1f 42 00 8b 0d 88 1f 42 00 c1 e1 05 33 0d 88 1f 42 00 89 0d 88 1f 42 00 a1 88 1f 42 00 8b e5 } //��B  7
	condition:
		((#a_80_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Amadey_A_AMTB_2{
	meta:
		description = "Trojan:Win32/Amadey.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_80_0 = {4d 6f 6e 65 72 6f 2d 73 74 6f 72 61 67 65 5c 77 61 6c 6c 65 74 73 5c } //Monero-storage\wallets\  4
		$a_80_1 = {5c 54 6f 72 42 72 6f 77 73 65 72 5c 44 61 74 61 5c 42 72 6f 77 73 65 72 5c 70 72 6f 66 69 6c 65 2e 64 65 66 61 75 6c 74 } //\TorBrowser\Data\Browser\profile.default  3
		$a_80_2 = {6d 6f 6e 65 72 6f 2d 77 61 6c 6c 65 74 2d 67 75 69 } //monero-wallet-gui  3
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3) >=10
 
}