
rule Trojan_iPhoneOS_WireLurker_D_xp{
	meta:
		description = "Trojan:iPhoneOS/WireLurker.D!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6d 61 6e 68 75 61 62 61 2e 6d 61 6e 68 75 61 6a 62 } //01 00  com.manhuaba.manhuajb
		$a_00_1 = {48 75 6e 61 6e 20 4c 61 6e 67 78 69 6f 6e 67 20 41 64 76 65 72 74 69 73 69 6e 67 20 44 65 63 6f 72 61 74 69 6f 6e 20 45 6e 67 69 6e 65 65 72 69 6e 67 20 43 6f } //01 00  Hunan Langxiong Advertising Decoration Engineering Co
		$a_00_2 = {35 39 37 53 38 37 42 38 38 45 } //01 00  597S87B88E
		$a_00_3 = {3a 2f 2f 77 77 77 2e 6d 61 6e 68 75 61 62 61 2e 63 6f 6d 2e 63 6e 2f 61 64 2f } //00 00  ://www.manhuaba.com.cn/ad/
		$a_00_4 = {5d 04 00 } //00 6e 
	condition:
		any of ($a_*)
 
}