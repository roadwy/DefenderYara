
rule Trojan_BAT_ClipBanker_GB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0d 00 00 0a 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 70 65 72 } //Clipper  01 00 
		$a_80_1 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  01 00 
		$a_80_2 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //schtasks.exe  01 00 
		$a_80_3 = {79 6d 6f 6e 65 79 } //ymoney  01 00 
		$a_80_4 = {70 61 79 65 65 72 } //payeer  01 00 
		$a_80_5 = {62 69 74 63 6f 69 6e } //bitcoin  01 00 
		$a_80_6 = {72 69 70 70 6c 65 } //ripple  01 00 
		$a_80_7 = {65 74 68 65 72 69 75 6d } //etherium  01 00 
		$a_80_8 = {6d 6f 6e 65 72 6f } //monero  01 00 
		$a_80_9 = {4c 69 74 65 43 6f 69 6e } //LiteCoin  01 00 
		$a_80_10 = {73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d 2f 74 72 61 64 65 6f 66 66 65 72 } //steamcommunity.com/tradeoffer  01 00 
		$a_80_11 = {64 6f 6e 61 74 69 6f 6e 61 6c 65 72 74 73 2e 63 6f 6d 2f } //donationalerts.com/  f6 ff 
		$a_80_12 = {73 6f 75 6e 64 65 72 } //sounder  00 00 
	condition:
		any of ($a_*)
 
}