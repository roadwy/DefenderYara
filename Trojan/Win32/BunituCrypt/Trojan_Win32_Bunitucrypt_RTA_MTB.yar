
rule Trojan_Win32_Bunitucrypt_RTA_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 00 10 00 00 83 c0 04 90 09 5a 00 90 02 20 33 90 02 16 8b 90 02 16 04 90 02 0a 04 90 02 0a 3b 90 02 0a 72 90 02 0a 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 02 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 3b 05 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 45 90 01 01 04 8b 90 01 02 83 c0 04 89 90 01 02 8b 90 01 02 3b 90 01 02 72 90 02 05 c7 90 01 02 00 10 00 00 8b 90 01 02 03 90 01 02 2b 90 01 02 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_5{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 6a 00 e8 90 01 04 8b d8 a1 90 01 04 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 33 18 89 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 0a 83 05 90 02 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_6{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 45 90 01 01 8b 55 90 01 01 01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 90 01 01 e8 90 01 04 8b d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_7{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //1
		$a_03_1 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 6a 90 01 01 e8 90 01 04 2b d8 8b 45 90 01 01 31 18 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_8{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 90 01 02 8b 90 01 02 3b 90 01 02 0f 90 00 } //1
		$a_03_1 = {2b d8 8b 45 90 01 01 31 18 6a 90 01 01 e8 90 01 04 8b d8 83 c3 04 6a 90 01 01 e8 90 01 04 2b d8 01 90 01 02 83 90 01 02 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RTA_MTB_9{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 00 } //1
		$a_03_1 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 6a 90 01 01 e8 90 01 04 2b d8 a1 90 01 04 31 18 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}