
rule Trojan_Win32_Ursnif_MK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 48 29 c3 81 fb ?? ?? ?? ?? 75 f3 } //1
		$a_03_1 = {ac 30 d0 aa c1 ca ?? e2 f7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ursnif_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 03 d1 8d 8a ?? ?? ?? ?? 2b ce 8b f1 1b c7 8b f8 3b 54 24 14 74 0e 8b 44 24 10 40 89 44 24 10 83 f8 ?? 7c d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_MK_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 65 f8 00 25 ?? ?? ?? ?? 81 6d f8 ?? ?? ?? ?? bb ?? ?? ?? ?? 81 45 f8 ?? ?? ?? ?? 8b 4d f8 83 25 ?? ?? ?? ?? ?? 8b c7 d3 e0 8b cf c1 e9 05 03 4d dc 03 45 e0 33 c1 8b 4d f4 03 cf 33 c1 29 45 fc 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_MK_MTB_4{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 89 55 f8 25 ?? ?? ?? ?? 81 6d f8 ?? ?? ?? ?? bb ?? ?? ?? ?? 81 45 f8 ?? ?? ?? ?? 8b 45 fc 8b 4d f8 8b f0 d3 e6 8b c8 c1 e9 05 03 4d e0 03 75 e4 89 15 ?? ?? ?? ?? 33 f1 8b 4d f4 03 c8 33 f1 8b 0d ?? ?? ?? ?? 2b fe 81 f9 ?? ?? ?? ?? 75 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_MK_MTB_5{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 33 45 0c 89 45 08 8b 4d fc 81 e9 ?? ?? ?? ?? 89 4d fc 8b 55 fc 81 c2 ?? ?? ?? ?? 89 55 fc c1 45 08 04 8b 45 fc 05 ?? ?? ?? ?? 89 45 fc 8b 45 fc 33 d2 b9 ?? ?? ?? ?? f7 f1 89 45 fc 8b 55 08 81 c2 ?? ?? ?? ?? 89 55 08 8b 45 fc 05 ?? ?? ?? ?? 89 45 fc 8b 45 08 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_MK_MTB_6{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 30 8b 4c 24 20 66 8b 14 48 66 89 d6 66 83 ?? ?? c7 44 24 60 ?? ?? ?? ?? 66 89 d7 66 83 c7 ?? 66 83 fe ?? 66 0f 42 d7 8b 44 24 58 35 ?? ?? ?? ?? 8b 5c 24 0c 89 5c 24 60 8b 74 24 10 66 39 14 4e 0f 94 c3 80 e3 01 88 5c 24 43 8b 74 24 0c 69 f6 ?? ?? ?? ?? 66 83 fa 00 0f 95 c3 8a 7c 24 43 89 74 24 60 8b 74 24 34 01 c1 39 f1 0f 92 c0 20 df 20 c7 89 4c 24 20 f6 c7 01 75 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_MK_MTB_7{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 6c 24 1c 4e 8d 84 30 ?? ?? ?? ?? 0f b7 d0 8a 04 2f 88 07 89 54 24 10 8b 15 ?? ?? ?? ?? 47 3b d3 77 1e 0f b6 c1 66 0f b6 c9 66 03 cb 66 83 e9 ?? 66 01 4c 24 10 8a 4c 24 10 a3 ?? ?? ?? ?? 2a cb 0f b7 6c 24 10 8b 44 24 14 2b c5 03 c6 3b d3 77 12 0f b6 d1 89 15 90 1b 03 8a d0 2a d3 80 ea ?? 02 ca 85 f6 75 98 } //1
		$a_03_1 = {3b 05 d0 00 03 10 74 1a 8b 15 ?? ?? ?? ?? 29 11 8b f2 69 f6 ?? ?? 00 00 2b f0 8b c6 03 d0 8d 5c 13 ca 83 e9 08 81 f9 ?? ?? ?? ?? 7f d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}