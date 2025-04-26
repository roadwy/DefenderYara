
rule Trojan_iPhoneOS_WireLurker_A_xp{
	meta:
		description = "Trojan:iPhoneOS/WireLurker.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 63 6f 6d 65 69 6e 62 61 62 79 2e 63 6f 6d } //2 www.comeinbaby.com
		$a_00_1 = {63 6f 6d 2e 62 61 62 79 2e 61 70 70 73 } //1 com.baby.apps
		$a_00_2 = {5a 32 45 52 36 47 33 50 43 37 } //1 Z2ER6G3PC7
		$a_00_3 = {6b 69 6c 6c 61 6c 6c 20 53 70 72 69 6e 67 42 6f 61 72 64 } //1 killall SpringBoard
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}