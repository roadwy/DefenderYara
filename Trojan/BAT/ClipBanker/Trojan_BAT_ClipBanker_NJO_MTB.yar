
rule Trojan_BAT_ClipBanker_NJO_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {33 38 38 33 35 35 63 34 2d 38 35 36 31 2d 34 34 63 30 2d 38 65 36 39 2d 33 30 32 35 63 31 66 32 33 64 31 36 } //2 388355c4-8561-44c0-8e69-3025c1f23d16
		$a_81_1 = {43 6c 69 70 70 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Clipper.My.Resources
		$a_81_2 = {50 61 74 74 65 72 6e 52 65 67 65 78 } //1 PatternRegex
		$a_81_3 = {43 6c 69 70 62 6f 61 72 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 ClipboardNotification
		$a_81_4 = {63 75 72 72 65 6e 74 43 6c 69 70 62 6f 61 72 64 } //1 currentClipboard
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}