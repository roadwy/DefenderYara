
rule PWS_Win32_Fareit_AD_MTB{
	meta:
		description = "PWS:Win32/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 ff 34 0e bb ?? ?? ?? ?? 5a 31 da 89 14 08 90 05 30 03 d9 d0 90 83 e9 04 7d ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_AD_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00 ff d0 90 0a 25 00 a1 ?? ?? ?? ?? 48 66 81 38 4d 5a 75 f8 05 ?? ?? ?? ?? 8b 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_AD_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f9 00 7f 90 0a ff 00 49 [0-08] 49 [0-08] 49 [0-08] 49 [0-10] ff 34 0f [0-30] 31 34 24 [0-30] 8f 04 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_AD_MTB_4{
	meta:
		description = "PWS:Win32/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 40 42 0f 00 [0-25] 81 c3 0d 18 81 00 [0-25] 39 18 75 [0-60] ff d3 [0-10] e8 ?? ?? 00 00 [0-10] b9 41 41 41 41 [0-10] 46 [0-0a] ff 37 [0-0a] 31 34 24 [0-15] bb 00 60 00 00 [0-15] 83 eb 04 [0-10] ff 34 1f [0-0a] 31 f2 [0-0a] 89 14 18 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}