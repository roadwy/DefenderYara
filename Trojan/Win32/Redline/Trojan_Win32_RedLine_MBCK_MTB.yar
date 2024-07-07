
rule Trojan_Win32_RedLine_MBCK_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c6 33 c1 2b f8 89 44 24 10 8b c7 c1 e0 04 81 3d 90 01 04 8c 07 00 00 89 44 24 0c 75 16 90 00 } //1
		$a_03_1 = {31 74 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 81 3d 90 01 04 93 00 00 00 75 10 90 00 } //1
		$a_03_2 = {8b c7 c1 e8 05 8d 34 3b c7 05 90 01 04 19 36 6b ff c7 05 90 01 04 ff ff ff ff 89 44 24 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}