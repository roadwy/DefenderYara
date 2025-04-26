
rule Trojan_Win32_Glupteba_GKM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c9 85 c0 76 ?? 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 88 14 0e 3d 03 02 00 00 75 ?? 83 25 14 d9 ?? ?? ?? ?? 3b c8 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 8d 0c 30 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? c1 e6 04 03 f5 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 03 f0 8d 0c 2f 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8d 14 37 31 54 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f7 c1 e6 04 03 74 24 ?? 8d 0c 3b 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 8d 0c 38 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b f7 c1 e6 04 03 b4 24 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 14 0e 3d 03 02 00 00 75 ?? 89 3d ?? ?? ?? ?? 41 3b c8 72 } //1
		$a_02_1 = {30 04 37 83 fb 19 75 ?? 33 c0 50 8d 4c 24 ?? 51 50 50 50 50 ff 15 ?? ?? ?? ?? 46 3b f3 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_8{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? ?? 44 24 ?? 8b 44 24 ?? 8d 14 37 33 c2 31 44 24 ?? 83 3d ?? ?? ?? ?? 42 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 44 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_9{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 03 f2 03 eb 33 f5 33 74 24 ?? 2b fe 81 3d ?? ?? ?? ?? 17 04 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_10{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 4c 24 ?? 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 44 24 ?? 8d 0c 37 33 c1 31 44 24 ?? 83 3d ?? ?? ?? ?? 42 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 44 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_11{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 45 ?? 81 05 ?? ?? ?? ?? 7e 32 ef 01 01 05 ?? ?? ?? ?? 8b 4d ?? 33 4d ?? 89 4d ?? 81 3d ?? ?? ?? ?? 83 05 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_12{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 cf 33 ce 2b d9 81 3d ?? ?? ?? ?? 17 04 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_13{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 85 ?? ?? ?? ?? 03 c3 33 45 ?? 33 db 33 c1 81 3d ?? ?? ?? ?? e6 06 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 45 ?? 75 } //1
		$a_02_1 = {c1 ea 05 03 ce 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b c6 c1 e0 04 03 c5 33 44 24 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 33 c1 81 3d ?? ?? ?? ?? e6 06 00 00 89 44 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}