
rule Trojan_Win32_Azorult_RTH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ee 05 03 90 02 05 83 90 02 05 1b 8d 90 02 03 89 90 02 05 c7 05 90 02 05 fc 03 cf ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 85 90 01 04 8d 0c 16 33 c1 31 45 90 01 01 81 3d 90 02 05 a3 01 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 90 01 02 c7 90 01 05 84 cd 10 fe 8b 90 01 02 81 90 02 09 01 90 01 05 83 90 02 09 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d9 8b 4d 90 01 01 d3 ea c7 90 02 0a 2e ce 50 91 03 55 90 01 01 33 d3 89 55 90 01 01 83 f8 27 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 90 01 01 c7 90 01 05 84 cd 10 fe 8b 90 01 02 81 90 02 09 01 90 01 05 8b 90 01 02 33 90 01 02 89 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 55 e0 89 55 90 01 01 c7 05 90 01 04 82 cd 10 fe 8b 90 01 02 81 05 90 01 04 7e 32 ef 01 01 90 01 05 8b 90 01 02 33 05 90 01 04 89 90 01 02 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d 90 01 01 50 03 fe 8d 45 90 01 01 33 cf 50 c7 05 90 01 01 b4 21 e1 c5 90 00 } //1
		$a_03_1 = {b8 2c 19 00 00 e8 90 01 04 56 33 f6 81 3d 90 01 04 77 01 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}