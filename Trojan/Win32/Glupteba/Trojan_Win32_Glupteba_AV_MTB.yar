
rule Trojan_Win32_Glupteba_AV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 c3 9e 26 00 a3 90 01 04 8a 0d 90 01 04 30 0c 1e 83 ff 19 75 0b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_AV_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f9 6c 75 0b b8 56 c4 08 00 01 05 90 01 04 41 81 f9 0f 7e 49 00 7c e7 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_AV_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 2e 15 8b 15 90 01 04 88 0c 32 3d 03 02 00 00 75 27 90 00 } //1
		$a_00_1 = {75 03 83 c1 15 40 3d 45 74 8d 00 7c ee } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Glupteba_AV_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d cc 6b 84 00 75 06 81 c1 f5 94 08 00 40 3d 45 74 8d 00 7c eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_AV_MTB_5{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d cc 6b 84 00 75 03 83 c1 15 40 3d 45 74 8d 00 7c ee } //1
		$a_01_1 = {30 04 33 83 ff 19 75 2e 6a 00 8d 44 24 10 50 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Glupteba_AV_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 10 8b 44 24 14 33 d7 33 c2 2b f0 81 c5 47 86 c8 61 83 ac 24 ac 02 00 00 01 0f 85 a7 e6 ff ff 8b 84 24 f8 06 00 00 5f 89 30 5e 5d 89 58 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_AV_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 83 c0 15 57 8b bc 24 f8 02 00 00 a3 } //1
		$a_01_1 = {30 04 33 83 ff 19 75 2e 6a 00 8d 44 24 10 } //1
		$a_01_2 = {8a 54 31 15 88 14 33 33 db 3d 03 02 00 00 75 19 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}