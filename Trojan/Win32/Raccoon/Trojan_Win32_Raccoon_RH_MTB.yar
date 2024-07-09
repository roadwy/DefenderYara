
rule Trojan_Win32_Raccoon_RH_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 44 24 7c 8e ac 58 26 81 44 24 60 66 92 e6 2b 81 44 24 30 e5 ae fc 48 8a 9c 02 3b 2d 0b 00 88 1c 30 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 08 00 81 01 e1 34 ef c6 c3 } //1
		$a_03_1 = {d3 e8 89 45 f4 8b 45 d4 01 45 f4 8b 45 f4 33 45 e8 89 35 ?? ?? ?? ?? 31 45 fc 2b 5d fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RH_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 0f 00 00 c7 04 24 f0 43 03 00 75 08 6a 00 ff 15 ?? ?? ?? ?? 56 83 44 24 04 0d a1 ?? ?? ?? ?? 0f af 44 24 04 05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13 00 00 a3 ?? ?? ?? ?? 0f b7 35 ?? ?? ?? ?? 75 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RH_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c2 01 89 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 3b 05 ?? ?? ?? ?? 73 ?? 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ff ff 0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RH_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 [0-10] 89 45 ?? 8b 45 ?? 01 45 ?? 03 f3 33 75 ?? 33 75 } //1
		$a_01_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}