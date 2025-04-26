
rule Trojan_Win32_Glupteba_KMG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d0 c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? ?? 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 44 24 ?? ?? 44 24 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 84 24 ?? ?? ?? ?? ?? 44 24 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? 8b 45 ?? ?? 45 ?? 8b 45 ?? ?? f0 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? 8b 45 ?? ?? 45 fc 8b 45 ?? 8b df c1 e3 04 03 5d ?? ?? c7 33 d8 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 10 8b 0d ?? ?? ?? ?? 40 3b c1 72 } //1
		$a_02_1 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? 01 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 75 05 0f 00 8b 1d ?? ?? ?? ?? 01 45 ?? ?? 5d ?? 8b 45 ?? 8a 14 08 a1 ?? ?? ?? ?? 88 14 08 } //1
		$a_02_1 = {30 04 16 42 3b d7 7c 90 09 05 00 e8 6b ff ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Glupteba_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {c1 e0 04 03 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 33 45 ?? 33 c1 2b f0 8b de c1 e3 04 81 3d ?? ?? ?? ?? 8c 07 00 00 89 45 ?? 75 } //1
		$a_02_1 = {c1 e9 05 89 4d ?? 8b 45 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 33 45 } //1
		$a_02_2 = {33 c1 2b f8 8b f7 c1 e6 04 81 3d ?? ?? ?? ?? 8c 07 00 00 89 45 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}