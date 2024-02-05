
rule Trojan_Win32_Glupteba_GKM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c9 85 c0 76 90 01 01 8b 15 90 01 04 8a 94 0a 90 01 04 8b 35 90 01 04 88 14 0e 3d 03 02 00 00 75 90 01 01 83 25 14 d9 90 01 04 3b c8 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 8d 0c 30 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 c1 e6 04 03 f5 33 f1 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 03 f0 8d 0c 2f 33 f1 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 90 01 01 89 4c 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8d 14 37 31 54 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b f7 c1 e6 04 03 74 24 90 01 01 8d 0c 3b 33 f1 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 8d 0c 38 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b f7 c1 e6 04 03 b4 24 90 01 04 c7 05 90 01 04 36 06 ea e9 33 f1 81 3d 90 01 04 f5 03 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 14 0e 3d 03 02 00 00 75 90 01 01 89 3d 90 01 04 41 3b c8 72 90 00 } //01 00 
		$a_02_1 = {30 04 37 83 fb 19 75 90 01 01 33 c0 50 8d 4c 24 90 01 01 51 50 50 50 50 ff 15 90 01 04 46 3b f3 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_8{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 90 01 01 89 4c 24 90 01 01 8b 84 24 90 01 05 44 24 90 01 01 8b 44 24 90 01 01 8d 14 37 33 c2 31 44 24 90 01 01 83 3d 90 01 04 42 c7 05 90 01 04 36 06 ea e9 89 44 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_9{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 08 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 54 24 90 01 01 03 f2 03 eb 33 f5 33 74 24 90 01 01 2b fe 81 3d 90 01 04 17 04 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_10{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 4c 24 90 01 01 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 44 24 90 01 01 8d 0c 37 33 c1 31 44 24 90 01 01 83 3d 90 01 04 42 c7 05 90 01 04 36 06 ea e9 89 44 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_11{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {d3 ea 89 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 c7 05 90 01 04 82 cd 10 fe 8b 45 90 01 01 81 05 90 01 04 7e 32 ef 01 01 05 90 01 04 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 81 3d 90 01 04 83 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_12{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 01 04 c6 0e 00 00 75 90 01 01 6a 00 6a 00 ff 15 90 01 04 6a 00 6a 00 ff 15 90 01 04 8b 4c 24 90 01 01 33 cf 33 ce 2b d9 81 3d 90 01 04 17 04 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GKM_MTB_13{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 85 90 01 04 01 45 90 01 01 8b 85 90 01 04 03 c3 33 45 90 01 01 33 db 33 c1 81 3d 90 01 04 e6 06 00 00 c7 05 90 01 04 36 06 ea e9 89 45 90 01 01 75 90 00 } //01 00 
		$a_02_1 = {c1 ea 05 03 ce 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b c6 c1 e0 04 03 c5 33 44 24 90 01 01 c7 05 90 01 04 36 06 ea e9 33 c1 81 3d 90 01 04 e6 06 00 00 89 44 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}