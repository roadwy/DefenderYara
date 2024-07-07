
rule Trojan_Win32_Guloader_AV_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c2 f5 94 08 00 89 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_AV_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.AV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 01 24 0a 00 a3 } //1
		$a_01_1 = {01 44 24 10 8b 4c 24 10 33 cf 33 ce 2b d9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Guloader_AV_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.AV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f8 6c 75 06 81 c1 1c a9 08 00 40 3d 0f 7e 49 00 7c } //1
		$a_01_1 = {01 04 24 b8 1c a9 08 00 01 04 24 8b 04 24 8a 14 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Guloader_AV_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.AV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f8 6c 75 06 81 c1 bc 2f 0a 00 40 3d 0f 7e 49 00 7c } //1
		$a_01_1 = {01 04 24 b8 bc 2f 0a 00 01 04 24 8b 04 24 8a 14 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}