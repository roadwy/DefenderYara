
rule Trojan_BAT_ClipBanker_GA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 2d 6d 61 73 74 65 72 5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 5c 90 02 32 2e 70 64 62 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_BAT_ClipBanker_GA_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  10
		$a_80_1 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //AddClipboardFormatListener  10
		$a_80_2 = {57 4d 5f 43 4c 49 50 42 4f 41 52 44 55 50 44 41 54 45 } //WM_CLIPBOARDUPDATE  1
		$a_80_3 = {63 75 72 72 65 6e 74 43 6c 69 70 62 6f 61 72 64 } //currentClipboard  1
		$a_80_4 = {52 65 67 65 78 } //Regex  1
		$a_80_5 = {65 74 68 65 72 65 75 6d } //ethereum  1
		$a_80_6 = {41 70 61 72 74 6d 65 6e 74 53 74 61 74 65 } //ApartmentState  1
		$a_80_7 = {28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 33 35 7d } //(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}  1
		$a_80_8 = {62 30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d } //b0x[a-fA-F0-9]{40}  1
		$a_80_9 = {62 34 28 5b 30 2d 39 5d 7c 5b 41 2d 42 5d 29 28 2e 29 7b 39 33 7d } //b4([0-9]|[A-B])(.){93}  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=26
 
}