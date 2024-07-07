
rule Trojan_iPhoneOS_WireLurker_B_xp{
	meta:
		description = "Trojan:iPhoneOS/WireLurker.B!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 62 6d 6f 2e 69 6e 66 6f 73 65 63 2e 74 65 73 74 2e 74 65 73 74 } //2 com.bmo.infosec.test.test
		$a_00_1 = {3a 2f 2f 77 77 77 2e 63 6f 6d 65 69 6e 62 61 62 79 2e 63 6f 6d 2f } //1 ://www.comeinbaby.com/
		$a_00_2 = {37 38 35 34 50 41 41 42 4a 38 } //1 7854PAABJ8
		$a_00_3 = {6b 69 6c 6c 61 6c 6c 20 53 70 72 69 6e 67 42 6f 61 72 64 } //1 killall SpringBoard
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}