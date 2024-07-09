
rule Trojan_Win32_BunituCrypt_RTH_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 10 33 c0 [0-14] 83 c0 04 01 [0-14] 83 c0 04 } //1
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 10 8b 45 ?? 03 45 ?? 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 6a [0-1e] a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 02 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 a1 } //1
		$a_03_1 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? e8 } //1
		$a_03_1 = {89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 } //1
		$a_03_1 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? eb ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_7{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 8b 55 ?? 01 10 a1 ?? ?? ?? ?? 05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_8{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-09] 0e 00 00 00 } //2
		$a_03_1 = {31 02 83 45 [0-05] 04 83 [0-05] 04 [0-0a] 0f [0-12] 2d 00 10 00 00 ?? ?? 04 } //1
		$a_03_2 = {31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 5d e4 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_9{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 } //1
		$a_02_1 = {03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 89 18 68 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}