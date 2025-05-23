
rule Trojan_BAT_FormBook_EVW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 06 17 da 8c ?? ?? ?? 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 09 11 06 09 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 da 13 07 11 04 11 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 06 17 d6 13 06 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_EVW_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.EVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {00 4c 6f 6e 67 50 61 74 68 44 69 72 65 63 74 6f 72 79 00 } //1
		$a_01_1 = {00 53 74 72 69 6e 67 54 79 70 65 49 6e 66 6f 00 } //1 匀牴湩呧灹䥥普o
		$a_01_2 = {00 49 6e 70 75 74 42 6c 6f 63 6b 53 69 7a 65 00 } //1 䤀灮瑵求捯卫穩e
		$a_01_3 = {00 45 73 63 61 70 65 64 49 52 65 6d 6f 74 69 6e 67 46 6f 72 6d 61 74 74 65 72 00 } //1
		$a_01_4 = {00 78 31 30 00 70 72 6f 6a 65 63 74 6e 61 6d 65 00 } //1
		$a_01_5 = {00 4c 6f 77 65 73 74 42 72 65 61 6b 49 74 65 72 61 74 69 6f 6e 00 } //1 䰀睯獥䉴敲歡瑉牥瑡潩n
		$a_01_6 = {00 44 61 74 61 4d 69 73 61 6c 69 67 6e 65 64 00 } //1 䐀瑡䵡獩污杩敮d
		$a_01_7 = {00 44 69 72 65 63 74 6f 72 79 49 6e 66 6f 00 } //1
		$a_01_8 = {00 4f 41 41 2e 64 6c 6c 00 } //1
		$a_01_9 = {00 45 6e 75 6d 43 61 74 65 67 6f 72 69 65 73 46 6c 61 67 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}