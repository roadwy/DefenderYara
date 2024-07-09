
rule Trojan_Win32_Azorult_RF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e ce 50 91 03 45 ?? 33 c7 83 3d ?? ?? ?? ?? 27 89 45 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d ec 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 [0-05] fc 03 cf ff 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 ?? ?? ?? ?? ee 3d ea f4 03 9d ?? ?? ?? ?? 33 da 83 3d [0-0a] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ?? 83 3d ?? ?? ?? ?? 1b 89 45 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc 03 cf ff [0-09] 1b 75 90 09 3c 00 [0-3c] ec [0-09] e0 [0-09] ec [0-09] c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? c7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Azorult_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 2e eb ed 8b ?? ?? 8b ?? ?? 8d 1c 38 8b c7 d3 e8 8b ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_9{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 05 03 55 ?? c7 [0-0a] b4 02 d7 cb c7 [0-0a] 89 ?? ?? 89 ?? ?? 8b ?? ?? 31 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 4d e0 89 4d ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? 83 ?? ?? ?? ?? ?? 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b ?? ?? 33 c3 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 26 04 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_12{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d1 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 33 c2 89 45 ?? 81 fe a3 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 33 ?? ?? 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_14{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 45 ?? 81 05 ?? ?? ?? ?? 7e 32 ef 01 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 0d ?? ?? ?? ?? 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_15{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 03 4d ?? 89 4d ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 55 ?? 33 55 ?? 89 55 ?? 81 3d ?? ?? ?? ?? 8d 00 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RF_MTB_16{
	meta:
		description = "Trojan:Win32/Azorult.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 8d 54 05 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ff ff ff ff 89 } //1
		$a_03_1 = {c1 e0 04 89 [0-0a] 01 [0-05] 8b [0-05] 8b [0-05] 03 c8 81 3d [0-05] be 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}