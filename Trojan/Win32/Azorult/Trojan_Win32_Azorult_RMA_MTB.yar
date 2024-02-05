
rule Trojan_Win32_Azorult_RMA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 90 01 05 2e ce 50 91 89 90 01 02 8d 90 01 02 e8 90 01 04 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {25 bb 52 c0 5d 8b 55 90 01 01 8b 7d 90 01 01 8b ca c1 e1 04 03 4d 90 01 01 8b c2 c1 e8 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8d 04 16 31 85 90 01 04 8b 85 90 01 04 31 45 90 01 01 81 3d 90 01 04 a3 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RMA_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 90 01 04 ee 3d ea f4 03 45 90 01 01 33 c3 81 3d 90 01 04 b7 01 00 00 89 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RMA_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c3 89 44 24 90 01 01 8b 90 02 0a c1 ee 05 03 74 24 90 01 01 83 3d 90 01 04 1b c7 05 90 01 04 fc 03 cf ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_RMA_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 18 53 8b 1d 90 01 04 56 8b 35 90 01 04 33 c0 57 8b 3d 90 01 04 89 45 90 01 01 eb 90 01 01 8d 49 90 01 01 81 3d 90 01 04 3f 12 00 00 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}