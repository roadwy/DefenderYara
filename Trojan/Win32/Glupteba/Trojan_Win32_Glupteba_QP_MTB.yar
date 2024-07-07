
rule Trojan_Win32_Glupteba_QP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {be d8 85 40 00 09 c0 e8 90 01 04 31 33 43 68 90 01 04 58 48 39 d3 75 e6 48 21 f8 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_QP_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 90 02 02 8b 90 02 02 03 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 29 90 02 02 8b 90 02 02 29 90 02 02 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}