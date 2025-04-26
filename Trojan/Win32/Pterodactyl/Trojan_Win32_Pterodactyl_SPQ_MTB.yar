
rule Trojan_Win32_Pterodactyl_SPQ_MTB{
	meta:
		description = "Trojan:Win32/Pterodactyl.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 63 64 66 76 67 4f 6a 6d 6e 68 } //1 RcdfvgOjmnh
		$a_81_1 = {57 63 65 66 4d 6e 79 62 72 } //1 WcefMnybr
		$a_81_2 = {58 72 63 74 76 79 62 4b 6e 75 62 79 76 } //1 XrctvybKnubyv
		$a_81_3 = {74 66 75 79 75 6b 74 79 2e 64 6c 6c } //1 tfuyukty.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}