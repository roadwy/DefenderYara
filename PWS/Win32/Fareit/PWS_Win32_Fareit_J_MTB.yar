
rule PWS_Win32_Fareit_J_MTB{
	meta:
		description = "PWS:Win32/Fareit.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5e 31 30 57 81 f7 90 02 ff 5f 39 18 0f 85 90 01 02 ff ff 90 00 } //1
		$a_02_1 = {5f 01 c8 56 81 d6 90 01 04 81 d6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule PWS_Win32_Fareit_J_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 07 b8 01 00 00 00 eb 02 33 c0 90 05 04 01 90 8b 5d 90 01 01 03 de 89 5d 90 01 01 90 05 04 01 90 85 c0 75 90 01 01 90 05 04 01 90 8a 1a 88 5d 90 01 01 90 05 04 01 90 8b 5d 90 01 01 8b fb 8a 5d 90 01 01 88 1f 90 05 04 01 90 46 90 05 04 01 90 42 49 75 90 00 } //1
		$a_03_1 = {33 c0 5a 59 59 64 89 10 68 90 01 04 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}