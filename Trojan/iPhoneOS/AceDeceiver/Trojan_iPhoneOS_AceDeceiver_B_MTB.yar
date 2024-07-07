
rule Trojan_iPhoneOS_AceDeceiver_B_MTB{
	meta:
		description = "Trojan:iPhoneOS/AceDeceiver.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 6f 6f 6c 2e 76 65 72 69 66 79 2e 69 34 2e 63 6e 2f 74 6f 6f 6c 43 68 65 63 6b 2e 78 68 74 6d 6c } //2 tool.verify.i4.cn/toolCheck.xhtml
		$a_00_1 = {70 61 73 73 77 6f 72 64 6b 65 79 31 32 33 } //1 passwordkey123
		$a_00_2 = {78 69 75 66 75 2e 69 34 2e 63 6e } //1 xiufu.i4.cn
		$a_00_3 = {61 69 73 69 77 65 62 5f 77 61 6c 6c 50 61 70 65 72 } //1 aisiweb_wallPaper
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}