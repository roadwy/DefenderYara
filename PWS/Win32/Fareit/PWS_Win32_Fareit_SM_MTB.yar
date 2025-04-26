
rule PWS_Win32_Fareit_SM_MTB{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 90 5c 8e 45 00 32 15 f8 2c 46 00 90 90 90 8b c7 03 c3 90 90 8b f0 90 8b c6 e8 8d fd ff ff 90 90 90 90 90 43 81 fb 12 5b 00 00 75 } //2
		$a_03_1 = {89 f6 89 f6 89 f6 8b c1 be 03 00 00 00 33 d2 f7 f6 85 d2 75 1e 89 f6 89 f6 8b c3 03 c1 73 05 e8 4f af f9 ff 89 f6 89 f6 89 f6 89 f6 89 f6 80 30 [0-04] 89 f6 89 f6 41 81 f9 [0-04] 75 c2 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1) >=2
 
}
rule PWS_Win32_Fareit_SM_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 19 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 } //2
		$a_00_1 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 50 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc } //2
		$a_00_2 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 3e 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc } //2
		$a_02_3 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 [0-04] 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*1) >=2
 
}
rule PWS_Win32_Fareit_SM_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 83 e2 01 85 d2 75 0e 8b d3 03 d0 73 05 e8 60 d1 f8 ff 80 32 9c 40 3d bc 18 01 00 75 e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule PWS_Win32_Fareit_SM_MTB_4{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb 01 00 00 00 90 90 90 90 8b c2 03 c3 90 90 90 c6 00 94 90 90 90 90 43 81 fb 7f 2f 4b 22 75 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_SM_MTB_5{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f6 89 f6 89 f6 8b c1 be 03 00 00 00 33 d2 f7 f6 85 d2 75 1e 89 f6 89 f6 8b c3 03 c1 73 05 e8 4f af f9 ff 89 f6 89 f6 89 f6 89 f6 89 f6 80 30 27 89 f6 89 f6 41 81 f9 a1 f7 00 00 75 c2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule PWS_Win32_Fareit_SM_MTB_6{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f6 89 f6 89 f6 89 f6 8b c1 bb 03 00 00 00 33 d2 f7 f3 85 d2 75 28 89 f6 89 f6 89 f6 8b d6 03 d1 89 f6 89 f6 89 f6 89 f6 b0 29 89 f6 89 f6 89 f6 89 f6 89 f6 30 02 89 f6 89 f6 89 f6 89 f6 89 f6 89 f6 89 f6 41 81 f9 16 1f 01 00 75 b2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_SM_MTB_7{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 7d e8 00 76 30 8b 45 e8 83 e0 03 85 c0 75 15 8b 45 e8 8a 80 88 80 46 00 34 71 8b 55 fc 03 55 e8 88 02 eb 11 8b 45 e8 8a 80 88 80 46 00 8b 55 fc 03 55 e8 88 02 ff 45 e8 81 7d e8 22 83 00 00 75 be } //2
		$a_01_1 = {85 c0 76 20 8b c8 83 e1 03 85 c9 75 0e 8a 0a 80 f1 f5 8b 5d fc 03 d8 88 0b eb 09 8b 4d fc 03 c8 8a 1a 88 19 40 42 3d a1 7c 00 00 75 d3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}