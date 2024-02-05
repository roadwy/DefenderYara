
rule Trojan_Win32_Gozi_GE_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 03 05 90 01 04 23 c6 a3 90 01 04 8d 80 90 01 04 8a 18 88 10 88 19 0f b6 00 0f b6 cb 03 c8 23 ce 8a 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 53 c7 04 e4 ff ff 0f 00 59 ff b3 90 01 04 8f 45 90 01 01 ff 75 90 01 01 58 53 c7 04 e4 90 01 04 8f 83 90 01 04 21 8b 90 01 04 01 83 90 01 04 ff a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GE_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {7e ea 00 00 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 05 d0 b4 07 01 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 89 91 90 01 04 0f b7 05 90 01 04 69 c8 7e ea 00 00 03 0d 90 01 04 66 89 0d 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GE_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 45 e8 be 90 01 04 8d 7d 90 01 01 a5 a5 a5 8b 55 90 01 01 33 55 90 01 01 8d 71 90 01 01 03 55 90 01 01 8b ce 03 55 90 02 06 d3 ea 52 8b 55 90 01 01 8d 0c 02 e8 90 00 } //0a 00 
		$a_02_1 = {8b 04 0a 8b f8 85 c0 75 90 02 0a eb 90 01 01 2b 74 24 90 01 01 03 c6 89 01 8b f7 83 c1 04 90 02 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GE_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 45 e8 be 90 01 04 8d 7d 90 01 01 a5 a5 a5 8b 55 90 01 01 33 55 90 01 01 8d 71 90 01 01 03 55 90 01 01 8b ce 03 55 90 01 01 d3 ea 52 8b 55 90 01 01 8d 0c 02 e8 90 00 } //0a 00 
		$a_02_1 = {8b 04 0a 85 c0 8b f8 75 90 01 01 33 db 43 eb 90 01 01 2b 74 24 90 01 01 03 c6 89 01 8b f7 83 c1 04 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GE_MTB_6{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 c6 0f b6 ca 2b c8 a1 90 01 04 83 c0 90 01 01 03 c1 a3 90 01 04 eb 0a 2a 05 90 01 04 04 90 01 01 02 d0 0f b6 c2 81 c7 90 01 04 66 03 c3 89 3d 90 01 04 66 03 f0 8b 44 24 90 01 01 83 44 24 90 01 01 04 66 89 74 24 90 01 01 89 38 8a 44 24 90 01 01 8a c8 2a 4c 24 90 01 01 80 c1 90 01 01 02 d1 83 6c 24 90 01 01 01 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}