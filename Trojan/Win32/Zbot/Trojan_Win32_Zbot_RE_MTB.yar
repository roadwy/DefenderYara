
rule Trojan_Win32_Zbot_RE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2a 40 00 64 2a 40 00 58 2a 40 00 4c 2a 40 00 40 2a 40 00 34 2a 40 00 20 2a 40 00 14 2a 40 00 0c 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be c9 89 cb 09 fb 31 c3 89 de c1 e6 0a 89 f7 } //1
		$a_01_1 = {70 69 6b 6d 6b 67 63 79 76 74 66 6b 79 68 65 69 71 67 68 67 } //1 pikmkgcyvtfkyheiqghg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}