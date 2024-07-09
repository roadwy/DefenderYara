
rule Trojan_Win32_BunituCrypt_GKM_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 7a 14 00 00 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 02 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c9 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? e8 ?? ?? ?? ?? 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}