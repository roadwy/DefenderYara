
rule Trojan_BAT_ClipBanker_GF_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  01 00 
		$a_80_1 = {42 54 43 20 53 74 65 61 6c 65 72 } //BTC Stealer  01 00 
		$a_80_2 = {5e 5b 31 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 33 33 7d 24 } //^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$  01 00 
		$a_80_3 = {42 69 74 43 6f 69 6e } //BitCoin  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_ClipBanker_GF_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 70 65 72 } //Clipper  01 00 
		$a_80_1 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  01 00 
		$a_80_2 = {52 65 67 65 78 } //Regex  01 00 
		$a_80_3 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //AddClipboardFormatListener  01 00 
		$a_80_4 = {40 65 63 68 6f 20 6f 66 66 } //@echo off  01 00 
		$a_80_5 = {53 54 41 52 54 20 22 22 } //START ""  01 00 
		$a_80_6 = {4c 65 67 65 6e 64 68 6f 74 20 54 65 61 6d } //Legendhot Team  01 00 
		$a_80_7 = {5e 62 63 31 5b 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 47 48 4a 4b 4c 4d 4e 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 5d 2e 2a 24 } //^bc1[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz].*$  01 00 
		$a_80_8 = {5e 30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 24 } //^0x[a-fA-F0-9]{40}$  01 00 
		$a_80_9 = {5e 28 71 7c 70 29 5b 61 2d 7a 30 2d 39 5d 7b 34 31 7d 24 } //^(q|p)[a-z0-9]{41}$  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_ClipBanker_GF_MTB_3{
	meta:
		description = "Trojan:BAT/ClipBanker.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 71 36 79 4b 53 50 70 6e 71 4d 7a 79 34 7a 32 43 5a 51 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {48 42 57 61 51 46 54 67 50 4d 6b 68 4e 67 54 54 67 62 66 } //01 00 
		$a_01_3 = {61 35 50 72 52 43 67 48 44 49 38 42 63 4b 47 64 38 53 69 } //01 00 
		$a_01_4 = {54 6f 53 74 72 69 6e 67 } //01 00 
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_6 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_81_7 = {47 65 74 53 74 72 69 6e 67 } //01 00 
		$a_81_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_81_9 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //01 00 
		$a_81_10 = {68 74 74 70 73 3a 2f 2f 69 70 76 34 62 6f 74 2e 77 68 61 74 69 73 6d 79 69 70 61 64 64 72 65 73 73 2e 63 6f 6d 2f } //00 00 
	condition:
		any of ($a_*)
 
}