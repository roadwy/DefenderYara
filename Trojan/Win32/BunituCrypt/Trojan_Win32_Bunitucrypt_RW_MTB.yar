
rule Trojan_Win32_Bunitucrypt_RW_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 90 01 01 03 45 90 01 01 2d 67 2b 00 00 03 45 90 01 01 03 d8 e8 90 01 04 2b d8 8b 45 90 01 01 31 18 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 0f e0 e0 5d 0d 00 90 00 } //1
		$a_03_1 = {31 02 6a 00 e8 90 01 04 8b d8 8b 45 90 01 01 83 c0 04 03 d8 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 90 01 01 03 90 01 02 03 90 01 02 8b 90 01 02 31 02 83 90 01 02 04 83 90 01 02 04 8b 90 01 02 3b 90 01 02 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 90 01 01 a1 90 01 04 03 05 90 01 04 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_5{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 6a 0c e8 90 01 04 8b d8 83 c3 04 6a 0c e8 90 01 04 2b d8 01 5d 90 01 01 83 45 90 01 01 04 90 00 } //1
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_6{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d f2 05 00 00 03 90 01 02 8b 90 01 05 31 02 90 02 05 e8 90 01 04 8b d8 83 c3 04 90 02 05 e8 90 01 04 2b d8 01 90 01 02 83 90 01 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_7{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 0f 90 00 } //1
		$a_03_1 = {31 02 83 05 90 01 04 04 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_8{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 00 10 00 00 83 90 01 01 04 90 09 70 00 90 02 20 a1 90 02 09 03 90 02 14 8b 90 02 14 31 90 02 50 83 90 02 09 04 83 90 02 09 04 90 02 0f 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_9{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 00 } //1
		$a_03_1 = {03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 00 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_10{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_11{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 a1 90 01 04 8b 15 90 01 04 01 02 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_12{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 90 01 02 8b 90 01 02 3b 90 01 02 73 90 00 } //1
		$a_03_1 = {2b d8 8b 45 90 01 01 31 18 83 90 01 02 04 83 90 01 02 04 8b 90 01 02 3b 90 01 02 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_13{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 10 6a 01 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 05 83 45 90 02 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_14{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 00 } //1
		$a_03_1 = {2b d8 a1 94 90 01 03 31 18 e8 90 01 04 8b d8 a1 90 01 04 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_15{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 01 04 8b 45 90 01 01 8b 55 90 01 01 01 02 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_16{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 a1 90 01 04 8b 15 90 01 04 01 02 90 00 } //1
		$a_03_1 = {31 18 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_17{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 45 90 01 01 33 c0 90 00 } //5
		$a_03_1 = {01 02 8b 45 90 01 01 03 90 01 02 03 90 01 02 8b 90 01 02 31 02 68 90 01 04 e8 90 01 04 83 90 01 02 04 83 90 01 02 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Bunitucrypt_RW_MTB_18{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //1
		$a_03_1 = {89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 15 90 01 04 31 02 a1 90 01 04 83 c0 90 01 01 a3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}