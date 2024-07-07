
rule Trojan_Win32_Glupteba_GT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 0f 29 c0 21 d8 81 c7 04 00 00 00 39 f7 75 eb 42 81 c2 90 01 04 c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 0e 01 da 81 c6 90 01 04 81 c2 90 01 04 29 d0 39 fe 75 e5 c3 90 00 } //10
		$a_03_1 = {31 0b 81 c2 90 01 04 4e 81 c3 90 01 04 4a bf 90 01 04 39 c3 75 e2 81 ee 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}