
rule Trojan_Win32_Oficla_L{
	meta:
		description = "Trojan:Win32/Oficla.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b7 da 31 c3 31 c0 81 fb 90 01 04 0f 93 c0 69 c0 90 1b 00 c7 44 24 90 01 03 00 10 90 00 } //1
		$a_01_1 = {85 f6 ba 39 00 00 00 74 0b b8 39 00 00 00 31 d2 f7 f6 } //1
		$a_01_2 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 } //1
		$a_01_3 = {30 01 83 c1 01 83 fa 10 75 ec 83 c3 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}