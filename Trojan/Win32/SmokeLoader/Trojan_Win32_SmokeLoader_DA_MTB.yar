
rule Trojan_Win32_SmokeLoader_DA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 4c 24 1c 8b 54 24 18 d3 ea 8b cd 8d 44 24 28 89 54 24 28 e8 [0-04] 8b 44 24 20 31 44 24 10 81 3d [0-04] 21 01 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_SmokeLoader_DA_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f b6 48 02 eb } //1
		$a_01_1 = {83 c1 01 eb } //1
		$a_01_2 = {51 91 59 eb } //1
		$a_01_3 = {b9 ad 2e 00 00 eb } //1
		$a_01_4 = {f7 e1 eb 05 } //1
		$a_01_5 = {01 d8 74 07 } //1
		$a_01_6 = {89 44 24 fc 83 ec 04 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}