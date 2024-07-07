
rule Trojan_Win32_Bunitucrypt_RMA_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d f2 05 00 00 03 05 90 01 04 8b 15 90 01 04 31 02 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 2d 16 00 00 6a 00 e8 90 01 04 03 d8 68 2d 16 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 90 01 02 33 c0 90 00 } //1
		$a_03_1 = {01 02 8b 45 90 01 01 03 90 02 05 03 90 02 05 8b 90 01 02 31 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 90 01 01 03 45 90 01 01 2d 29 09 00 00 03 45 90 01 01 03 d8 6a 00 e8 90 01 04 2b d8 8b 45 90 01 01 31 18 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_5{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 90 01 01 04 83 90 01 05 04 8b 90 01 02 3b 90 01 05 72 90 01 01 a1 90 01 04 03 90 01 05 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_6{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 05 0e 00 00 00 90 00 } //1
		$a_03_1 = {31 18 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 01 90 02 1e 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_7{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 6a 02 e8 90 01 04 8b d8 83 c3 04 6a 02 e8 90 01 04 2b d8 01 1d 90 01 04 83 05 90 01 04 04 90 00 } //1
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_8{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 31 18 6a 00 e8 90 01 04 8b d8 8b 45 90 01 01 83 c0 04 03 d8 6a 00 e8 90 01 04 2b d8 89 90 02 05 8b 90 02 05 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_9{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 00 10 00 00 90 02 0a 83 05 90 02 05 04 90 09 5a 00 90 02 20 31 90 02 0a a1 90 02 07 04 01 05 90 02 14 04 01 05 90 02 14 3b 90 02 0a 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_10{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 05 0e 00 00 00 90 00 } //5
		$a_03_1 = {33 02 89 45 90 02 0a 89 02 90 02 0a 04 90 02 0a 04 90 00 } //1
		$a_00_2 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_11{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 90 02 05 0e 00 00 00 90 00 } //1
		$a_03_1 = {01 02 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 01 01 04 6a 00 e8 90 01 04 8b d8 83 c3 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_12{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 90 02 05 0e 00 00 00 90 00 } //1
		$a_03_1 = {31 02 83 05 90 01 04 04 83 05 90 01 04 04 90 02 46 3b 05 90 01 04 72 90 02 10 2d 00 10 00 00 90 01 02 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_13{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 31 18 6a 90 01 01 e8 90 01 04 8b d8 83 c3 04 6a 90 01 01 e8 90 01 04 2b d8 01 5d 90 01 01 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_14{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 90 01 01 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e0 0f 82 90 01 04 c7 45 90 01 01 00 10 00 00 8b 45 90 01 01 03 45 90 01 01 2b 45 90 01 01 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_15{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 6a 90 01 01 e8 90 00 } //1
		$a_03_1 = {31 18 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 90 01 01 a1 90 01 04 03 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_16{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 90 01 05 0f 90 01 05 a1 90 01 04 03 90 01 05 2d 00 10 00 00 83 c0 04 90 00 } //1
		$a_03_1 = {8a a5 08 00 a1 90 01 04 3b 90 01 05 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}