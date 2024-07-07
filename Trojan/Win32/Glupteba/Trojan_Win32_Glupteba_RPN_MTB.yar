
rule Trojan_Win32_Glupteba_RPN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 db 74 01 ea 31 17 90 02 10 81 c7 04 00 00 00 90 02 10 39 c7 75 e6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPN_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 d8 85 40 00 83 ec 04 c7 04 24 f2 6d eb 01 5b 81 c2 3f 8f 8c e1 e8 1b 00 00 00 81 c3 91 fb 44 88 4a 31 01 41 21 da 01 d2 39 f1 75 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}