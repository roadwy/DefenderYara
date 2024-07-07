
rule Trojan_Win32_BunituCrypt_RM_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 90 02 0e 6a 90 00 } //1
		$a_03_1 = {03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 0f 90 00 } //2
		$a_03_1 = {03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 33 c0 89 45 90 01 01 8b 45 90 01 01 83 c0 04 01 45 90 01 01 8b 45 90 01 01 83 c0 04 90 00 } //1
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 05 90 02 14 8b 15 90 02 1a 83 90 02 0a 04 83 90 02 0a 04 a1 90 01 04 3b 05 90 01 04 0f 90 02 19 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 0a e3 14 00 00 90 00 } //1
		$a_03_1 = {2b d8 8b 45 90 01 01 31 18 83 45 90 01 01 04 6a 00 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 8d 85 90 01 04 33 c9 ba 3c 00 00 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_7{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 0f 90 01 05 a1 90 01 04 8b 90 01 05 01 10 a1 90 01 04 03 90 01 05 03 90 01 05 8b 90 01 05 31 02 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_8{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d 90 01 04 6a 00 90 02 32 a1 90 01 04 8b 15 90 01 04 89 02 6a 00 90 02 0a 83 c3 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 14 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_9{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 10 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 83 c0 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 0a 83 05 90 02 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_10{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 02 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 01 04 c7 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_11{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_12{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 02 0a 8a a5 08 00 90 00 } //1
		$a_03_1 = {89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 00 e8 90 01 04 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_13{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 05 90 01 04 04 83 90 01 05 04 6a 90 02 05 e8 90 01 04 a1 90 01 04 3b 90 01 05 72 90 02 04 a1 90 01 04 03 90 01 05 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_14{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 5d 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 10 6a 01 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 05 83 45 90 02 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_15{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 b0 8a a5 08 00 90 02 08 00 00 00 90 00 } //1
		$a_03_1 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 00 e8 90 01 04 8b d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_16{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 10 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 01 01 8b 45 90 01 01 03 45 90 01 01 2d 00 10 00 00 90 02 05 83 45 90 02 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_17{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 05 90 01 04 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 89 02 6a 0c e8 90 01 04 8b d8 83 c3 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 0a 83 90 02 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_18{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 73 90 00 } //5
		$a_03_1 = {31 02 83 05 90 01 04 04 83 90 01 05 04 a1 90 01 04 3b 90 01 05 72 90 01 01 a1 90 01 04 03 90 01 05 2d 00 10 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_19{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 6a 00 e8 90 01 04 6a 00 e8 90 01 04 6a 00 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_20{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 0f 90 00 } //1
		$a_03_1 = {31 02 83 05 90 01 04 04 e8 90 01 04 8b d8 83 c3 04 e8 90 01 04 2b d8 01 1d 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_21{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 0f 83 90 00 } //1
		$a_03_1 = {10 6a 00 e8 90 01 04 8b d8 a1 90 01 04 03 90 01 05 03 90 01 05 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_22{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 90 01 01 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
		$a_03_1 = {8a a5 08 00 33 c0 89 90 01 02 33 c0 89 90 01 02 33 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_23{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 00 } //1
		$a_03_1 = {31 18 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 01 1d 90 01 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_24{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 03 d8 68 61 1e 00 00 6a 90 00 } //1
		$a_03_1 = {68 61 1e 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 6a 00 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_25{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 4f 0c 00 00 6a 00 e8 90 01 04 03 d8 68 4f 0c 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 90 00 } //1
		$a_03_1 = {89 18 68 4f 0c 00 00 6a 00 e8 90 01 04 8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_26{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 6a 90 00 } //1
		$a_03_1 = {8b 00 03 05 90 01 04 03 d8 6a 90 01 01 e8 90 01 04 2b d8 a1 90 01 04 89 18 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_27{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 0f 90 00 } //1
		$a_03_1 = {8b 00 03 05 90 01 04 03 d8 e8 90 01 04 2b d8 a1 90 01 04 89 18 e8 90 01 04 8b d8 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 03 d8 e8 90 01 04 2b d8 a1 90 01 04 31 18 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_28{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //1
		$a_03_1 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 6a 90 01 01 e8 90 01 04 2b d8 8b 45 90 01 01 31 18 83 90 01 02 04 83 90 01 02 04 8b 90 01 02 3b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_29{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 90 01 02 3b 90 01 02 0f 90 00 } //5
		$a_03_1 = {2b d8 8b 45 90 01 01 89 18 8b 90 01 02 03 90 01 02 03 90 01 02 8b 90 01 02 31 02 83 90 01 02 04 83 90 01 02 04 90 00 } //1
		$a_03_2 = {8b d8 8b 45 90 01 01 03 90 01 02 03 90 01 02 03 d8 6a 00 e8 90 01 04 2b d8 8b 90 01 02 31 18 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=6
 
}
rule Trojan_Win32_BunituCrypt_RM_MTB_30{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 0f 90 00 } //5
		$a_03_1 = {8b d8 83 c3 04 e8 90 01 04 2b d8 01 1d 90 01 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 0f 90 09 0e 00 2b d8 a1 90 01 04 31 18 e8 90 00 } //1
		$a_03_2 = {8b d8 83 c3 04 e8 90 01 04 2b d8 90 09 15 00 03 d8 e8 90 01 04 2b d8 a1 90 01 04 31 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=6
 
}