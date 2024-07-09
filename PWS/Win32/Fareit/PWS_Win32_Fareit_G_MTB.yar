
rule PWS_Win32_Fareit_G_MTB{
	meta:
		description = "PWS:Win32/Fareit.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 c3 53 8b d8 6a 00 e8 ?? ?? ?? ?? 90 90 90 90 8b c3 34 ?? 90 90 90 90 5b c3 53 56 57 55 51 8b da 8b f0 54 6a 40 68 ?? ?? ?? ?? 56 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_G_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff 34 0e 81 34 24 ?? ?? ?? ?? 8f 04 08 c3 } //1
		$a_02_1 = {00 00 59 83 e9 04 e8 ?? ff ff ff 83 e9 03 e0 f6 e8 ?? ff ff ff ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}