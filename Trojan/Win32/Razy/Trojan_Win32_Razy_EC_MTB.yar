
rule Trojan_Win32_Razy_EC_MTB{
	meta:
		description = "Trojan:Win32/Razy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {f8 3e 34 02 90 01 00 00 00 50 b3 02 f1 28 04 00 } //1
		$a_01_1 = {0f 01 0b 01 07 0a 00 60 12 00 00 30 05 01 00 00 00 00 b4 e8 44 02 } //1
		$a_01_2 = {10 d2 3b 01 00 70 77 01 00 e0 3b 01 } //1
		$a_01_3 = {f1 28 04 00 00 50 b3 02 00 30 04 00 00 f0 3b 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}