
rule Trojan_Win32_Azorult_RF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e ce 50 91 03 45 90 01 01 33 c7 83 3d 90 01 04 27 89 45 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d ec 8b 90 01 02 03 90 01 02 89 90 01 02 c7 90 02 05 fc 03 cf ff 81 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 90 01 04 2e ce 50 91 89 90 01 02 8b 90 01 02 01 90 01 02 81 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 90 01 04 ee 3d ea f4 03 9d 90 01 04 33 da 83 3d 90 02 0a 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 90 01 01 83 3d 90 01 04 1b 89 45 90 01 01 c7 05 90 01 04 fc 03 cf ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc 03 cf ff 90 02 09 1b 75 90 09 3c 00 90 02 3c ec 90 02 09 e0 90 02 09 ec 90 02 09 c7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 90 01 01 c7 90 01 05 84 cd 10 fe 8b 90 01 02 33 90 01 02 89 90 01 02 c7 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Azorult_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 2e eb ed 8b 90 01 02 8b 90 01 02 8d 1c 38 8b c7 d3 e8 8b 90 01 02 c7 90 01 05 2e ce 50 91 89 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_9{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 05 03 55 90 01 01 c7 90 02 0a b4 02 d7 cb c7 90 02 0a 89 90 01 02 89 90 01 02 8b 90 01 02 31 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 4d e0 89 4d 90 01 01 c7 05 90 01 04 82 cd 10 fe 8b 90 01 02 33 90 01 02 89 90 01 02 83 90 01 05 0f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 90 01 02 33 c3 31 90 01 02 8b 90 01 02 8d 90 01 05 e8 90 01 04 81 90 01 05 26 04 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_12{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d1 8b 4d 90 01 01 d3 e8 c7 05 90 01 04 ee 3d ea f4 03 45 90 01 01 33 c2 89 45 90 01 01 81 fe a3 01 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 90 01 01 8b 90 01 02 03 90 01 02 89 90 01 02 c7 05 90 01 04 82 cd 10 fe 8b 90 01 02 33 90 01 02 89 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_14{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 90 01 01 c7 05 90 01 04 82 cd 10 fe 8b 45 90 01 01 81 05 90 01 04 7e 32 ef 01 01 90 01 05 8b 90 01 02 33 0d 90 01 04 89 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_15{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 03 4d 90 01 01 89 4d 90 01 01 c7 05 90 01 04 82 cd 10 fe 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 81 3d 90 01 04 8d 00 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_16{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 8d 54 05 90 01 01 8d 44 24 90 01 01 c7 05 90 01 04 b4 02 d7 cb c7 05 90 01 01 ff ff ff ff 89 90 00 } //1
		$a_03_1 = {c1 e0 04 89 90 02 0a 01 90 02 05 8b 90 02 05 8b 90 02 05 03 c8 81 3d 90 02 05 be 01 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}