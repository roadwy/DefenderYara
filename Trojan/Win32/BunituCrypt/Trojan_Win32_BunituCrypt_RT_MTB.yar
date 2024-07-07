
rule Trojan_Win32_BunituCrypt_RT_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 7c 30 00 00 03 45 90 01 01 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 0e 00 00 03 90 02 0c e8 90 01 04 2b 90 02 08 a1 90 01 04 31 18 83 90 02 05 04 83 90 02 05 04 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 7c 30 00 00 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 00 e8 90 01 04 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 05 90 01 04 04 83 90 01 05 04 a1 90 01 04 3b 90 01 05 0f 90 01 05 a1 90 01 04 03 90 01 05 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 5d 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 10 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 a1 90 01 04 8b 15 90 01 04 01 10 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_7{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 10 00 00 83 c0 04 a3 } //1
		$a_03_1 = {8b d8 83 c3 04 e8 90 01 04 2b d8 01 1d 90 01 04 e8 90 01 04 8b d8 83 c3 04 e8 90 01 04 2b d8 01 90 01 05 68 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_8{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 68 90 01 04 e8 90 01 04 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_9{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 73 90 00 } //2
		$a_03_1 = {2b d8 03 1d 90 01 04 a1 90 01 04 89 18 a1 90 01 04 03 90 01 05 03 90 01 05 8b 90 01 05 31 02 6a 00 e8 90 01 04 8b d8 83 c3 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_10{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 31 18 6a 00 e8 90 01 04 6a 00 e8 90 01 04 6a 00 e8 90 01 04 6a 00 e8 90 01 04 6a 90 00 } //1
		$a_03_1 = {8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 03 d8 68 90 01 04 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_11{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 67 2b 00 00 03 90 01 02 8b 90 01 02 31 02 83 90 01 02 04 83 90 01 02 04 90 02 0a 72 90 00 } //1
		$a_03_1 = {2d f2 05 00 00 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 a0 99 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_12{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 05 0e 00 00 00 90 00 } //1
		$a_03_1 = {31 02 83 45 90 01 01 04 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 01 90 01 02 8b 90 01 02 3b 90 01 02 0f 90 02 14 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_13{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 90 01 02 e3 14 00 00 c7 90 01 02 9f 0a 00 00 90 00 } //1
		$a_03_1 = {33 c0 89 45 90 01 01 8b 45 90 01 01 8b 55 90 01 01 01 10 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_14{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 68 4f 0c 00 00 6a 00 e8 90 01 04 8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 03 d8 68 4f 0c 00 00 6a 00 e8 90 01 04 03 d8 68 4f 0c 00 00 90 00 } //1
		$a_03_1 = {03 d8 68 4f 0c 00 00 6a 00 e8 90 01 04 03 d8 68 4f 0c 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 6a 00 e8 90 01 04 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_15{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 05 0e 00 00 00 90 00 } //1
		$a_03_1 = {31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 01 01 8b 45 90 01 01 03 45 90 01 01 2d 00 10 00 00 83 c0 04 90 00 } //1
		$a_03_2 = {31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 90 02 05 3b 90 02 05 0f 90 02 19 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RT_MTB_16{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 0f 90 00 } //5
		$a_03_1 = {31 02 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 90 00 } //1
		$a_03_2 = {31 18 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 90 00 } //1
		$a_03_3 = {03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 83 90 01 05 04 83 90 01 05 04 a1 90 01 04 3b 90 01 05 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}