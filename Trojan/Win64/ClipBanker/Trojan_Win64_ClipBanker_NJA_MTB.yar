
rule Trojan_Win64_ClipBanker_NJA_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_81_0 = {44 69 61 6d 6f 74 72 69 78 } //2 Diamotrix
		$a_81_1 = {54 57 62 41 6b 58 71 32 53 75 70 59 55 36 75 6d 45 56 4d 76 78 57 68 41 41 37 74 38 4c 79 4c 57 4a 44 } //1 TWbAkXq2SupYU6umEVMvxWhAA7t8LyLWJD
		$a_81_2 = {30 78 32 32 39 31 64 36 30 35 66 36 66 64 33 65 37 65 33 39 37 34 64 37 35 66 37 63 31 63 65 66 33 36 61 61 38 65 38 65 33 61 } //1 0x2291d605f6fd3e7e3974d75f7c1cef36aa8e8e3a
		$a_81_3 = {5c 62 34 5b 30 2d 39 41 42 5d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 39 33 7d 5c 62 } //1 \b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b
		$a_81_4 = {5c 62 62 69 74 63 6f 69 6e 63 61 73 68 3a 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 34 32 7d 5c 62 } //1 \bbitcoincash:[a-zA-HJ-NP-Z0-9]{26,42}\b
		$a_81_5 = {31 48 32 37 63 33 77 5a 7a 53 65 62 48 43 59 56 68 66 6a 79 34 33 33 34 6a 46 64 79 4d 35 6b 48 73 42 } //1 1H27c3wZzSebHCYVhfjy4334jFdyM5kHsB
		$a_81_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_81_7 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=9
 
}