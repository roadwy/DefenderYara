
rule Trojan_iPhoneOS_YiSpecter_A_MTB{
	meta:
		description = "Trojan:iPhoneOS/YiSpecter.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 77 65 69 79 69 6e 67 2e 68 69 64 64 65 6e 49 63 6f 6e 4c 61 75 6e 63 68 } //2 com.weiying.hiddenIconLaunch
		$a_00_1 = {69 6f 73 6e 6f 69 63 6f 2e 62 62 38 30 30 2e 63 6f 6d } //1 iosnoico.bb800.com
		$a_00_2 = {48 69 64 64 65 6e 49 63 6f 6e 52 75 6e 42 61 63 6b 67 72 6f 75 6e 64 } //1 HiddenIconRunBackground
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}