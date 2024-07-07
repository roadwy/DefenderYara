
rule Trojan_Win32_Raccoon_RG_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 09 8b 85 90 01 02 ff ff 99 be 26 00 00 00 f7 fe 8b 85 90 01 02 ff ff 0f b6 14 10 33 ca 8b 85 90 01 02 ff ff 03 85 90 01 02 ff ff 88 08 eb aa 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RG_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 08 89 54 24 04 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 04 31 04 24 8b 04 24 89 01 83 c4 08 c2 04 00 90 02 10 81 01 e1 34 ef c6 c3 90 02 10 29 11 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RG_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 01 08 c3 } //1
		$a_03_1 = {36 dd 96 53 81 45 90 01 01 38 dd 96 53 8b 4d 90 01 01 8b c6 d3 e0 90 02 20 8b c6 d3 e8 89 55 90 01 01 89 3d 90 01 04 03 45 90 01 01 33 c2 31 45 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RG_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 90 01 01 38 dd 96 53 8b 4c 24 90 01 01 8b d6 d3 e2 90 02 30 8b c6 d3 e8 03 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 31 4c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RG_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 7c f6 ff ff 83 c0 01 89 85 7c f6 ff ff 8b 8d 7c f6 ff ff 3b 0d 90 01 04 73 27 0f b6 15 90 01 04 a1 90 01 04 03 85 7c f6 ff ff 0f b6 08 33 ca 8b 15 90 01 04 03 95 7c f6 ff ff 88 0a eb bc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RG_MTB_7{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 45 90 01 01 38 dd 96 53 8b 4d 90 01 01 8b c6 d3 e0 90 02 10 8b 45 90 01 01 03 c6 89 45 90 01 01 8b c6 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 02 0a 31 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}