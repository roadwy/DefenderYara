
rule Trojan_Win32_Glupteba_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 06 89 d2 81 c6 01 00 00 00 39 de 75 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_GMZ_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 07 51 5b 81 c7 04 00 00 00 39 f7 ?? ?? 21 da c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_GMZ_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ca 31 3e 29 c2 40 f7 d2 46 21 c9 29 c8 48 43 21 d0 48 81 fe } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}