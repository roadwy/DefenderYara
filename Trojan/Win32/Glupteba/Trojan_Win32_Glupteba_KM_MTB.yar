
rule Trojan_Win32_Glupteba_KM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8d 0c 37 31 4c 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ee 05 89 74 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 94 24 90 01 04 8d 34 17 33 f1 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KM_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 03 f1 8d 14 3b 33 f2 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KM_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 8c 24 90 01 04 03 f1 8d 14 2f 33 f2 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KM_MTB_5{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 84 24 90 01 04 03 f0 8d 0c 2f 33 f1 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KM_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 14 06 88 14 38 40 3b c1 72 } //1
		$a_02_1 = {c1 ea 05 89 54 24 90 01 01 c7 05 90 01 04 2e ce 50 91 8b 84 24 90 01 05 44 24 90 01 01 81 3d 90 01 04 12 09 00 00 75 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Glupteba_KM_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8d 4c 24 90 01 01 51 8d 54 24 90 01 01 52 50 89 44 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 ff d3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 57 e8 90 01 04 81 3d 90 01 04 60 0e 00 00 75 0c ff 15 90 01 04 ff 15 90 01 04 83 c7 08 83 ee 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KM_MTB_8{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 4c 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 94 24 90 01 04 03 f2 8d 04 2f 33 f0 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
		$a_02_1 = {c1 e9 05 89 4d 90 01 01 8b 85 90 01 04 01 45 90 01 01 8b 95 90 01 04 8b 85 90 01 04 03 f2 03 c7 33 f0 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KM_MTB_9{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {46 81 fe dc a8 29 00 7c 90 01 01 33 c0 3b cd 76 90 01 01 8b 35 90 01 04 eb 90 02 15 8a 94 06 f5 d0 00 00 8b 3d 90 01 04 88 14 07 40 3b c1 72 90 00 } //1
		$a_02_1 = {81 ec 68 08 00 00 a1 90 01 04 33 c4 89 84 24 90 01 04 81 3d 90 01 04 12 0f 00 00 56 75 90 01 01 6a 00 8d 44 24 08 50 6a 00 ff 15 90 01 04 8b 0d 90 01 04 69 c9 fd 43 03 00 89 0d 90 01 04 81 05 90 01 04 c3 9e 26 00 81 3d 90 01 04 a5 02 00 00 8b 35 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}