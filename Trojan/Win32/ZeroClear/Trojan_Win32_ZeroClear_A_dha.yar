
rule Trojan_Win32_ZeroClear_A_dha{
	meta:
		description = "Trojan:Win32/ZeroClear.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 45 d0 63 00 3a 00 } //1
		$a_01_1 = {c7 45 d4 5c 00 70 00 } //1
		$a_01_2 = {c7 45 d8 72 00 6f 00 } //1
		$a_01_3 = {c7 45 dc 67 00 72 00 } //1
		$a_01_4 = {c7 45 e0 61 00 6d 00 c7 45 e4 64 00 61 00 c7 45 e8 74 00 61 00 c7 45 ec 5c 00 77 00 c7 45 f0 6c 00 6f 00 c7 45 f4 67 00 2e 00 c7 45 f8 74 00 78 00 c7 45 fc 74 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}