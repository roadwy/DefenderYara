
rule PWS_Win32_Fareit_MTB{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 8b 1c 0a 81 f3 90 01 04 89 1c 08 f8 83 c1 04 81 f9 90 01 04 75 90 01 01 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_MTB_2{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 d9 04 0f 8d 90 01 02 ff ff 90 0a 00 02 89 1c 08 90 0a 00 02 81 f3 90 0a 00 02 8b 1c 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Fareit_MTB_3{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_02_1 = {83 fb 00 7f 90 0a c0 00 83 eb 04 90 02 20 ff 34 1f 90 02 20 8f 04 18 90 02 20 31 34 18 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule PWS_Win32_Fareit_MTB_4{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_02_1 = {83 f9 00 7f 90 0a 20 00 09 1c 08 90 0a 50 00 31 f3 90 0a 30 00 8b 1c 0f 90 0a 10 00 49 90 0a 10 00 49 90 0a 10 00 49 90 0a 10 00 49 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule PWS_Win32_Fareit_MTB_5{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_00_1 = {54 00 70 00 4a 00 6d 00 62 00 65 00 71 00 32 00 5a 00 75 00 55 00 30 00 37 00 69 00 66 00 35 00 52 00 69 00 48 00 79 00 67 00 30 00 37 00 55 00 41 00 39 00 41 00 5a 00 36 00 73 00 68 00 6a 00 31 00 39 00 } //1 TpJmbeq2ZuU07if5RiHyg07UA9AZ6shj19
		$a_02_2 = {83 fb 00 0f 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule PWS_Win32_Fareit_MTB_6{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_02_1 = {83 c7 04 85 90 0a ff 00 83 c2 04 90 0a ff 00 83 c4 04 90 0a ff 00 89 0c 18 90 0a ff 00 8b 0c 24 90 0a ff 00 31 34 24 90 0a ff 00 ff 37 90 00 } //1
		$a_02_2 = {83 c7 04 66 90 0a ff 00 83 c2 04 90 0a ff 00 83 c4 04 90 0a ff 00 89 0c 18 90 0a ff 00 8b 0c 24 90 0a ff 00 31 34 24 90 0a ff 00 ff 37 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
rule PWS_Win32_Fareit_MTB_7{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_02_1 = {8f 04 18 66 90 0a ff 00 ff 31 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //1
		$a_02_2 = {8f 04 18 81 90 0a ff 00 ff 31 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //1
		$a_02_3 = {8f 04 18 85 90 0a ff 00 ff 31 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}
rule PWS_Win32_Fareit_MTB_8{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_01_1 = {b8 00 10 b0 01 } //1
		$a_01_2 = {b8 00 10 b0 02 } //1
		$a_01_3 = {2d 00 00 70 01 } //1
		$a_01_4 = {2d 00 00 70 02 } //1
		$a_01_5 = {68 2f 37 02 00 } //1
		$a_01_6 = {81 c2 1e 23 8e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}