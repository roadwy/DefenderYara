
rule Trojan_Win32_Bunitucrypt_RMA_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d f2 05 00 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 ?? ?? 33 c0 } //1
		$a_03_1 = {01 02 8b 45 ?? 03 [0-05] 03 [0-05] 8b ?? ?? 31 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 03 45 ?? 2d 29 09 00 00 03 45 ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 6a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_5{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 ?? 04 83 ?? ?? ?? ?? ?? 04 8b ?? ?? 3b ?? ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_6{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-05] 0e 00 00 00 } //1
		$a_03_1 = {31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 [0-1e] 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_7{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 6a 02 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 02 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 } //1
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_8{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 83 c0 04 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 [0-05] 8b [0-05] 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_9{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 00 10 00 00 [0-0a] 83 05 [0-05] 04 90 09 5a 00 [0-20] 31 [0-0a] a1 [0-07] 04 01 05 [0-14] 04 01 05 [0-14] 3b [0-0a] 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_10{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-05] 0e 00 00 00 } //5
		$a_03_1 = {33 02 89 45 [0-0a] 89 02 [0-0a] 04 [0-0a] 04 } //1
		$a_00_2 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_11{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-05] 0e 00 00 00 } //1
		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_12{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 [0-05] 0e 00 00 00 } //1
		$a_03_1 = {31 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 [0-46] 3b 05 ?? ?? ?? ?? 72 [0-10] 2d 00 10 00 00 ?? ?? 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_13{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a ?? e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_14{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 ?? 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e0 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 8b 45 ?? 03 45 ?? 2b 45 ?? 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_15{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? 6a ?? e8 } //1
		$a_03_1 = {31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 ?? a1 ?? ?? ?? ?? 03 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMA_MTB_16{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04 } //1
		$a_03_1 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}