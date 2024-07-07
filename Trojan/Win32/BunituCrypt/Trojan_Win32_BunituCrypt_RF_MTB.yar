
rule Trojan_Win32_BunituCrypt_RF_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 31 0c 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 81 c2 8a a5 08 00 03 15 90 01 04 33 c2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 90 01 01 a1 90 01 04 03 05 90 01 04 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 e8 90 02 0e a1 90 01 04 8b 15 90 01 04 01 10 a1 90 02 16 31 02 83 05 90 01 04 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 10 33 c0 90 02 0a 8b d8 90 02 05 83 c0 04 90 02 0a 2b d8 01 90 02 0a 83 c0 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 05 83 45 ec 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 90 02 05 0e 00 00 00 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 83 c0 04 90 09 70 00 90 02 20 31 90 02 0a 04 90 02 0a 04 90 02 37 a1 90 02 09 3b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 6a 90 02 1e e8 90 01 04 a1 90 01 04 8b 15 90 01 04 01 10 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_7{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 03 e8 90 01 04 8b d8 a1 90 02 17 2b d8 a1 90 01 04 89 18 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 83 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_8{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 0f 90 00 } //1
		$a_03_1 = {8b 00 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 89 18 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_9{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 01 04 a1 90 01 04 8b 55 90 01 01 01 10 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 15 90 01 04 31 02 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_10{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 68 74 2d 4b 00 e8 90 01 04 68 74 2d 4b 00 e8 90 01 04 68 74 2d 4b 00 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_11{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 01 5d 90 01 01 8b 90 01 02 01 90 01 02 eb 90 01 01 8b 90 01 02 3b 90 01 02 73 90 01 01 8b 90 01 02 8b 90 01 02 01 02 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 8b 90 01 02 03 90 01 02 03 90 01 02 8b 90 01 02 31 02 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RF_MTB_12{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d8 68 2e 16 00 00 6a 00 e8 90 01 04 03 d8 a1 90 01 04 31 18 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 01 04 0f 82 90 00 } //1
		$a_03_1 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 2e 16 00 00 6a 00 e8 90 01 04 03 d8 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}