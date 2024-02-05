
rule Trojan_Win32_Gozi_GC_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b f8 89 bb 90 01 04 83 fb 00 76 90 02 1e fc f3 a4 57 c7 04 e4 ff ff 0f 00 59 8b 83 90 01 04 56 c7 04 e4 90 01 04 8f 83 90 01 04 21 8b 90 01 04 01 83 90 01 04 ff a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b c8 89 0d 90 01 04 0f b6 15 90 01 04 a1 90 01 04 8d 4c 02 90 01 01 89 0d 90 01 04 8b 55 90 01 01 81 ea 90 01 04 2b 15 90 01 04 89 15 90 01 04 8b 3d 90 01 04 41 83 c7 90 01 01 83 ef 90 01 01 41 ff e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 55 90 01 01 8b 45 90 01 01 8d 8c 10 90 01 04 89 4d 90 01 01 8b 15 90 01 04 89 15 90 01 04 8b 45 90 02 30 8b 4d 90 00 } //01 00 
		$a_02_1 = {8b ff c7 05 ec 90 02 30 01 05 90 02 30 8b ff a1 90 02 30 8b 0d 90 02 25 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GC_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 c0 99 33 f6 03 44 24 90 01 01 13 d6 03 d8 13 ea 8b c7 05 90 01 04 8a 10 8d 43 90 01 01 88 97 90 01 04 0f b7 d0 47 89 54 24 90 01 01 be 90 01 04 66 8b c2 83 3d 90 01 04 30 75 90 00 } //0a 00 
		$a_02_1 = {89 0e 89 0d 90 01 04 8a ca 02 c8 83 c6 04 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GC_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 75 0c 0f af c6 c6 05 90 01 04 00 69 c0 90 01 04 66 a3 90 01 04 8b 7d 90 01 01 81 c3 90 01 04 83 c7 03 03 d9 83 ef 03 ff d7 90 0a 4b 00 66 03 0d 90 01 04 83 05 90 01 04 57 66 89 0d 90 01 04 a1 90 00 } //0a 00 
		$a_02_1 = {64 ff 35 00 00 00 00 90 02 0c 2b e0 53 56 57 a1 90 01 04 31 45 90 01 01 33 c5 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}