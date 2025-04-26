
rule PWS_Win32_Fareit_H_MTB{
	meta:
		description = "PWS:Win32/Fareit.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5e 31 c9 b9 00 [0-4f] ff 34 0e [0-ff] 31 04 24 [0-ff] 0f 8d ?? ?? ff ff [0-9f] ff e4 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_H_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 07 b8 01 00 00 00 eb 02 33 c0 90 90 8b de 03 d9 73 05 e8 ?? ?? ?? ?? 89 5d f8 85 c0 75 1f 90 90 90 90 8a 1a 88 5d f7 90 90 90 90 8b 5d f8 8b fb 8a 5d f7 88 1f 83 c1 01 73 05 e8 ?? ?? ?? ?? 90 90 90 90 90 90 ff 45 fc 42 81 7d fc f1 e7 00 00 75 b3 } //1
		$a_03_1 = {33 c0 89 06 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ff 75 fc 90 90 58 90 90 f7 f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}