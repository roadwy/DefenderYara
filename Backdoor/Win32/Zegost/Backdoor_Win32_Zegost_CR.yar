
rule Backdoor_Win32_Zegost_CR{
	meta:
		description = "Backdoor:Win32/Zegost.CR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 85 c7 fc fe ff 64 c6 85 c8 fc fe ff 2e c6 85 c9 fc fe ff 25 c6 85 ca fc fe ff 64 } //1
		$a_01_1 = {c6 85 f5 fe ff ff 5c c6 85 f6 fe ff ff 52 c6 85 f7 fe ff ff 75 c6 85 f8 fe ff ff 6e } //1
		$a_01_2 = {67 67 66 25 63 25 63 25 63 25 63 25 63 63 6b 2e 65 78 65 00 } //1
		$a_01_3 = {7e 4d 00 00 48 7a 00 00 48 41 52 44 57 41 52 45 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}