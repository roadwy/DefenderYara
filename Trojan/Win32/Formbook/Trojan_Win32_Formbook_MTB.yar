
rule Trojan_Win32_Formbook_MTB{
	meta:
		description = "Trojan:Win32/Formbook!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 3a 8b c8 c1 e9 90 01 01 33 cf 81 e1 90 01 04 c1 e0 90 01 01 33 84 8d 90 01 04 42 4e 75 e2 90 00 } //1
		$a_02_1 = {b8 67 66 66 66 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 c2 8d 04 80 03 c0 03 c0 8b d1 2b d0 8a 04 3a 88 8c 0d 90 01 04 88 84 0d 90 01 04 41 81 f9 90 01 04 7c ca 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}