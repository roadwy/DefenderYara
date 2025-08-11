
rule Trojan_BAT_ClipBanker_NJK_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {5e 28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 33 39 7d 24 } //2 ^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$
		$a_81_1 = {5e 28 3f 3a 5b 4c 4d 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 36 2c 33 33 7d 29 24 } //1 ^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$
		$a_81_2 = {5e 28 62 69 74 63 6f 69 6e 63 61 73 68 3a 29 3f 28 71 7c 70 29 5b 61 2d 7a 30 2d 39 5d 7b 34 31 7d } //1 ^(bitcoincash:)?(q|p)[a-z0-9]{41}
		$a_81_3 = {44 65 63 72 79 70 74 44 61 74 61 } //1 DecryptData
		$a_81_4 = {45 6e 63 72 79 70 74 44 61 74 61 } //1 EncryptData
		$a_81_5 = {50 72 6f 63 65 73 73 43 6c 69 70 62 6f 61 72 64 43 6f 6e 74 65 6e 74 } //1 ProcessClipboardContent
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}