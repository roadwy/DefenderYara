
rule Trojan_Win32_Glupteba_AD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {31 3a 42 39 da 75 ec c3 8d 3c 37 8b 3f 40 09 c9 81 e7 90 01 04 29 c0 81 c6 90 01 04 40 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {40 21 c2 31 37 47 29 c2 01 d0 39 df 75 e5 } //02 00 
		$a_03_1 = {31 11 81 e8 01 00 00 00 81 ee 90 02 04 81 c1 04 00 00 00 39 f9 75 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}