
rule Trojan_Win32_Azorult_RMA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8d ?? ?? e8 ?? ?? ?? ?? 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 bb 52 c0 5d 8b 55 ?? 8b 7d ?? 8b ca c1 e1 04 03 4d ?? 8b c2 c1 e8 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8d 04 16 31 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RMA_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 33 c3 81 3d ?? ?? ?? ?? b7 01 00 00 89 45 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RMA_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c3 89 44 24 ?? 8b [0-0a] c1 ee 05 03 74 24 ?? 83 3d ?? ?? ?? ?? 1b c7 05 ?? ?? ?? ?? fc 03 cf ff 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RMA_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 18 53 8b 1d ?? ?? ?? ?? 56 8b 35 ?? ?? ?? ?? 33 c0 57 8b 3d ?? ?? ?? ?? 89 45 ?? eb ?? 8d 49 ?? 81 3d ?? ?? ?? ?? 3f 12 00 00 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}