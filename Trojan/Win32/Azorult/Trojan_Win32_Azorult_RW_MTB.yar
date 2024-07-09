
rule Trojan_Win32_Azorult_RW_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 2e eb ed 8b ?? ?? 8b c6 d3 e8 8b ?? ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 33 ?? 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 89 4c ?? ?? 8d [0-05] e8 ?? ?? ?? ?? 81 [0-0a] 8b [0-1e] fc 03 cf ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 ?? ?? ?? ?? ee 3d ea f4 03 9d ?? ?? ?? ?? 33 da 81 3d ?? ?? ?? ?? b7 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc 03 cf ff 90 09 3c 00 [0-3c] 05 03 ?? ?? 83 ?? ?? ?? ?? ?? 1b 89 [0-0a] c7 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ef 89 45 ?? c7 ?? ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 83 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c6 47 86 c8 61 ff 8d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8b 45 ?? 5f 89 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_8{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ?? c7 05 ?? ?? ?? ?? b4 02 d7 cb 89 45 ?? 33 45 ?? c7 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_9{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc 03 cf ff 8b 90 09 32 00 [0-32] d3 ?? 89 ?? ?? 8b ?? ?? 01 ?? ?? c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea c7 05 ?? ?? ?? ?? 2e ce 50 91 89 ?? ?? 8b ?? ?? 01 ?? ?? 81 ?? ?? ?? ?? ?? ff 03 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 83 7d ?? 19 75 ?? 53 53 53 53 ff 15 ?? ?? ?? ?? 47 3b 7d ?? 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_12{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 cb 8d 04 37 89 4c 24 ?? 8b d6 50 8d 4c 24 ?? c1 ea 05 51 c7 [0-05] b4 21 e1 c5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Azorult_RW_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 [0-05] 8b [0-0a] 03 c1 8b [0-0a] 33 [0-05] 83 3d [0-05] 27 c7 05 [0-05] 2e ce 50 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_14{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 51 8d ?? ?? 52 e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 91 05 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_15{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 b5 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 85 ?? ?? ?? ?? 03 c7 33 f0 81 3d ?? ?? ?? ?? 3f 0b 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_16{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? 82 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_17{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fe c3 14 0c 18 89 [0-05] 7c [0-05] 8b 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 33 c9 89 4c 24 ?? 8d 64 24 ?? 81 f9 0d 04 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_18{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b fe 8b c7 c1 e0 04 03 45 ?? 03 cf 81 3d ?? ?? ?? ?? be 01 00 00 } //1
		$a_03_1 = {c1 ea 05 03 55 ?? 50 8d 4d ?? 51 c7 05 ?? ?? ?? ?? b4 02 d7 cb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Azorult_RW_MTB_19{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 52 c0 5d 81 [0-09] 81 [0-09] 8b ?? ?? 8b ?? ?? 8b c2 d3 e0 89 } //1
		$a_03_1 = {40 2e eb ed 8b 4d ?? 03 cf 89 ?? ?? 8b ?? ?? 8b df d3 eb c7 ?? ?? ?? ?? ?? 2e ce 50 91 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RW_MTB_20{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8d 14 37 31 54 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
		$a_02_1 = {c1 ea 05 89 4c 24 ?? 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 44 24 ?? 8d 0c 37 33 c1 31 44 24 ?? 83 3d ?? ?? ?? ?? 42 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 44 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}