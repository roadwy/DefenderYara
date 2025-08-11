
rule Trojan_Win32_ClickFix_DEQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 4d 00 64 00 2e 00 45 00 78 00 45 00 20 00 2f 00 56 00 3a 00 4f 00 4e 00 20 00 2f 00 43 00 } //100 cMd.ExE /V:ON /C
		$a_00_1 = {6d 00 53 00 68 00 26 00 20 00 73 00 65 00 74 00 } //10 mSh& set
		$a_00_2 = {41 00 2e 00 65 00 58 00 45 00 26 00 } //10 A.eXE&
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}