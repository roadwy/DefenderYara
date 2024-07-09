
rule Trojan_Win32_Emotet_KMG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {be 27 16 00 00 99 f7 fe 33 c0 8a ?? ?? ?? 41 81 f9 27 16 00 00 8b f2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a d9 03 de 81 e3 ?? ?? ?? ?? 8b f3 8a 5c 34 ?? 88 5c 14 ?? 88 4c 34 ?? 0f b6 5c 14 ?? 0f b6 c9 03 d9 81 e3 ?? ?? ?? ?? 79 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d8 03 de 81 e3 ?? ?? ?? ?? 8b f3 8a 5c 34 ?? 88 5c 0c ?? 88 44 34 ?? 0f b6 5c 0c ?? 0f b6 c0 4d 03 d8 81 e3 ?? ?? ?? ?? 89 ac 24 ?? ?? ?? ?? 79 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c6 99 f7 f9 0f b6 04 3e 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 0f be 8a ?? ?? ?? ?? 03 cb 03 c1 99 b9 0f 27 00 00 f7 f9 } //1
		$a_00_1 = {0f b6 04 3e 8a 14 3b 88 14 3e 83 c6 01 81 fe 0f 27 00 00 88 04 3b 0f 8c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {99 8b ce f7 f9 0f b6 04 2f 8a 0c 3a 88 0c 2f 88 04 3a 0f b6 04 2f 89 54 24 1c 0f b6 14 3a } //1
		$a_02_1 = {f6 d2 f6 d1 0a d1 22 d3 88 10 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24 ?? 0f 85 } //1
		$a_02_2 = {f6 d2 0a d8 8b 44 24 ?? f6 d1 0a d1 22 d3 88 10 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a c8 88 44 24 ?? 03 cb 81 e1 ff 00 00 00 8b d9 8a 54 1c ?? 88 54 3c ?? 88 44 1c } //1
		$a_02_1 = {8a c8 88 44 24 ?? 03 cf 81 e1 ff 00 00 00 8b f9 8a 54 3c ?? 88 54 34 ?? 88 44 3c ?? e8 } //1
		$a_02_2 = {32 c2 88 45 00 8b 44 24 ?? 45 48 89 44 24 ?? 0f 85 } //1
		$a_02_3 = {40 8a 54 04 ?? 8a 03 32 c2 88 03 43 4d 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 3b 88 14 3b 43 3b de 88 01 7c a6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c6 be 7c 0d 00 00 99 f7 fe 33 c0 8a 04 39 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_9{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 3b 8a 11 83 c4 0c 88 14 3b 43 3b de 88 01 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_10{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 1f 8a 0c 2b 88 0c 1f 47 81 ff c1 05 00 00 88 04 2b 0f 8c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_11{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 fd 33 c0 8a 04 3e 0f be 0c 0a 03 d9 b9 c3 10 00 00 03 c3 99 f7 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_12{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 3d 27 16 00 00 7c } //1
		$a_01_1 = {8a d0 0a c1 f6 d2 0a d3 22 d0 8b 44 24 10 88 16 46 48 89 44 24 10 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_KMG_MTB_13{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c3 99 bb c1 05 00 00 f7 fb 0f b6 04 0f 89 7c 24 18 8a 1c 0a 88 1c 0f 88 04 0a 0f b6 04 0f 89 54 24 1c 0f b6 14 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_KMG_MTB_14{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 08 88 0a 8b 55 08 03 55 f0 8a 45 fc 88 02 8b 4d f0 83 e9 01 89 4d f0 eb } //1
		$a_01_1 = {61 6d 75 4e 78 45 63 6f 6c 6c 41 6c 61 75 74 72 69 56 } //1 amuNxEcollAlautriV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_KMG_MTB_15{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 1f 8a 0c 2b 88 0c 1f 47 81 ff 7c 0d 00 00 88 04 2b 0f 8c } //1
		$a_01_1 = {0f b6 04 2f 8a 14 2b 88 14 2f 83 c7 01 81 ff 7c 0d 00 00 88 04 2b 0f 8c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}