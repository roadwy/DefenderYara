
rule Trojan_Win32_ClipBanker_GA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2f 00 2f 00 0e 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  10
		$a_80_1 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //AddClipboardFormatListener  10
		$a_80_2 = {57 4d 5f 43 4c 49 50 42 4f 41 52 44 55 50 44 41 54 45 } //WM_CLIPBOARDUPDATE  1
		$a_80_3 = {63 75 72 72 65 6e 74 43 6c 69 70 62 6f 61 72 64 } //currentClipboard  1
		$a_80_4 = {52 65 67 65 78 } //Regex  10
		$a_80_5 = {62 69 74 63 6f 69 6e } //bitcoin  1
		$a_80_6 = {65 74 68 65 72 65 75 6d } //ethereum  1
		$a_80_7 = {6d 6f 6e 65 72 6f } //monero  1
		$a_80_8 = {72 69 70 70 6c 65 } //ripple  1
		$a_80_9 = {62 69 74 63 6f 69 6e 63 61 73 68 } //bitcoincash  1
		$a_80_10 = {6c 69 74 65 63 6f 69 6e } //litecoin  1
		$a_80_11 = {62 69 6e 61 6e 63 65 } //binance  1
		$a_80_12 = {74 65 7a 6f 73 } //tezos  1
		$a_80_13 = {5c 62 28 62 69 74 63 6f 69 6e 63 61 73 68 29 } //\b(bitcoincash)  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*10+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*10) >=47
 
}