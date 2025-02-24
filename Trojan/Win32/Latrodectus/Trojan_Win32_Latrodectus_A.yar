
rule Trojan_Win32_Latrodectus_A{
	meta:
		description = "Trojan:Win32/Latrodectus.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {b0 06 6a 90 } //1
		$a_01_1 = {87 b8 c9 d4 } //1
		$a_01_2 = {f6 b1 00 ff } //1
		$a_01_3 = {69 00 0d 66 19 00 } //1
		$a_01_4 = {c7 04 24 c5 9d 1c 81 } //1
		$a_01_5 = {69 04 24 93 01 00 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}