
rule Trojan_Win32_BunituCrypt_GKM_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 7a 14 00 00 6a 00 e8 90 01 04 03 05 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 02 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 6a 00 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 d8 68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c9 8b 55 90 01 01 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 e8 90 01 04 68 3b 11 00 00 6a 00 e8 90 01 04 03 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}