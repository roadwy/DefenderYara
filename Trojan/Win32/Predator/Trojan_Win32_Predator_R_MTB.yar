
rule Trojan_Win32_Predator_R_MTB{
	meta:
		description = "Trojan:Win32/Predator.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 ff d7 ff d3 81 fe [0-04] 7e 12 81 7d [0-05] 74 09 81 7d [0-05] 75 0b 46 81 fe [0-04] 7c d1 } //1
		$a_02_1 = {88 14 01 40 3b 05 ?? ?? ?? ?? 72 e1 90 09 13 00 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Predator_R_MTB_2{
	meta:
		description = "Trojan:Win32/Predator.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {46 3b f0 72 90 0a 66 00 3d 80 04 00 00 75 ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff } //1
		$a_02_1 = {8a c1 24 fc c0 e0 04 0a 44 33 01 8a d9 80 e1 f0 02 c9 02 c9 0a 0c 2e c0 e3 06 0a 5c 2e 02 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 04 42 3b 35 ?? ?? ?? ?? 72 bb 90 09 10 00 8b 1d ?? ?? ?? ?? 8a 4c 33 03 8b 2d } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Predator_R_MTB_3{
	meta:
		description = "Trojan:Win32/Predator.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {eb 0d 8b 85 ?? ?? ?? ?? 40 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 21 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8a 89 ?? ?? ?? ?? 88 08 eb c4 } //1
		$a_02_1 = {eb 07 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 7d 2a 8b 45 ?? 03 45 ?? 0f be 00 89 45 ?? e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 eb c7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Predator_R_MTB_4{
	meta:
		description = "Trojan:Win32/Predator.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_00_0 = {eb 09 8b 55 e8 03 55 f0 89 55 e8 8b 45 0c 8b 4d e8 3b 08 0f 83 fc 00 00 00 8b 55 08 8b 02 8b 4d e8 8a 14 08 88 55 ed 8b 45 08 8b 08 8b 55 e8 8a 44 0a 01 88 45 f7 8b 4d 08 8b 11 8b 45 e8 } //1
		$a_00_1 = {03 45 fc 8a 4d ed 88 08 8b 55 fc 83 c2 01 89 55 fc 8b 45 f8 03 45 fc 8a 4d f7 88 08 8b 55 fc 83 c2 01 89 55 fc 8b 45 f8 03 45 fc 8a 4d ef 88 08 8d 55 fc 52 e8 29 fe ff ff 83 c4 04 e9 ed fe ff ff } //1
		$a_02_2 = {0b c1 88 45 ?? 90 09 1b 00 c1 e1 ?? ?? ?? ?? ?? ?? ?? ?? 81 e2 } //5
		$a_02_3 = {0b d0 88 55 ?? 90 09 1b 00 c1 e0 ?? ?? ?? ?? ?? ?? ?? ?? 81 e1 } //5
		$a_02_4 = {0b ca 88 4d ?? 90 09 1a 00 c1 e2 ?? ?? ?? ?? ?? ?? ?? ?? 25 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_02_4  & 1)*5) >=17
 
}