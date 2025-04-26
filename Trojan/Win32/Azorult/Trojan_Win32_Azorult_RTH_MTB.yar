
rule Trojan_Win32_Azorult_RTH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ee 05 03 [0-05] 83 [0-05] 1b 8d [0-03] 89 [0-05] c7 05 [0-05] fc 03 cf ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 85 ?? ?? ?? ?? 8d 0c 16 33 c1 31 45 ?? 81 3d [0-05] a3 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 81 [0-09] 01 ?? ?? ?? ?? ?? 83 [0-09] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d9 8b 4d ?? d3 ea c7 [0-0a] 2e ce 50 91 03 55 ?? 33 d3 89 55 ?? 83 f8 27 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 81 [0-09] 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 55 e0 89 55 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 81 05 ?? ?? ?? ?? 7e 32 ef 01 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 05 ?? ?? ?? ?? 89 ?? ?? 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTH_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d ?? 50 03 fe 8d 45 ?? 33 cf 50 c7 05 ?? b4 21 e1 c5 } //1
		$a_03_1 = {b8 2c 19 00 00 e8 ?? ?? ?? ?? 56 33 f6 81 3d ?? ?? ?? ?? 77 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}