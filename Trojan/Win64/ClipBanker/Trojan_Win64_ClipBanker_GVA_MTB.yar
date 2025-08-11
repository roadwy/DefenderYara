
rule Trojan_Win64_ClipBanker_GVA_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //20 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {66 6d 74 5f 62 69 74 63 6f 69 6e } //3 fmt_bitcoin
		$a_01_2 = {66 6d 74 5f 65 74 68 65 72 65 75 6d } //3 fmt_ethereum
		$a_01_3 = {66 6d 74 5f 74 72 6f 6e } //3 fmt_tron
		$a_01_4 = {66 6d 74 5f 6d 6f 6e 65 72 6f } //3 fmt_monero
		$a_01_5 = {66 6d 74 5f 72 69 70 70 6c 65 } //3 fmt_ripple
		$a_01_6 = {66 6d 74 5f 63 61 72 64 61 6e 6f } //3 fmt_cardano
		$a_01_7 = {66 6d 74 5f 6c 69 74 65 63 6f 69 6e } //3 fmt_litecoin
		$a_01_8 = {66 6d 74 5f 64 6f 67 65 63 6f 69 6e } //3 fmt_dogecoin
		$a_01_9 = {66 6d 74 5f 73 6f 6c 61 6e 61 } //3 fmt_solana
		$a_01_10 = {66 6d 74 5f 63 6f 73 6d 6f 73 } //3 fmt_cosmos
		$a_01_11 = {66 6d 74 5f 74 65 72 72 61 } //3 fmt_terra
		$a_01_12 = {66 6d 74 5f 70 6f 6c 6b 61 64 6f 74 } //3 fmt_polkadot
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*3+(#a_01_11  & 1)*3+(#a_01_12  & 1)*3) >=29
 
}