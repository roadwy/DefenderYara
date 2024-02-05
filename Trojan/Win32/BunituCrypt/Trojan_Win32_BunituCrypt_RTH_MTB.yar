
rule Trojan_Win32_BunituCrypt_RTH_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 10 33 c0 90 02 14 83 c0 04 01 90 02 14 83 c0 04 90 00 } //01 00 
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 10 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 15 90 01 04 31 02 a1 90 01 04 83 c0 04 a3 90 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 6a 90 02 1e a1 90 01 04 8b 15 90 01 04 01 02 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 6a 90 01 01 e8 90 01 04 2b d8 a1 90 01 04 31 18 a1 90 00 } //01 00 
		$a_03_1 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 e8 90 00 } //01 00 
		$a_03_1 = {89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 00 } //01 00 
		$a_03_1 = {2b d8 01 5d 90 01 01 8b 45 90 01 01 01 45 90 01 01 eb 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_7{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 3b 05 90 01 04 73 90 01 01 a1 90 01 04 8b 55 90 01 01 01 10 a1 90 01 04 05 8a a5 08 00 03 45 90 01 01 8b 15 90 01 04 31 02 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_8{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 09 0e 00 00 00 90 00 } //01 00 
		$a_03_1 = {31 02 83 45 90 02 05 04 83 90 02 05 04 90 02 0a 0f 90 02 12 2d 00 10 00 00 90 01 02 04 90 00 } //01 00 
		$a_03_2 = {31 02 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 01 5d e4 6a 00 e8 90 01 04 8b d8 83 c3 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_BunituCrypt_RTH_MTB_9{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 90 01 04 03 55 90 01 01 03 55 90 01 01 33 c2 03 d8 68 d7 11 00 00 6a 00 e8 90 01 04 03 d8 68 d7 11 00 00 6a 00 e8 90 01 04 03 d8 68 d7 11 00 00 6a 00 e8 90 00 } //01 00 
		$a_02_1 = {03 d8 68 d7 11 00 00 6a 00 e8 90 01 04 03 d8 68 d7 11 00 00 6a 00 e8 90 01 04 03 d8 a1 90 01 04 89 18 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}