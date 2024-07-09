
rule Trojan_Win32_SmokeLoader_AD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 05 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {89 7c 24 fc 83 ec 04 90 13 56 90 13 90 13 ba ?? ?? ?? ?? 90 13 e8 00 00 00 00 90 13 5e 90 13 90 13 81 ee ?? ?? ?? ?? 90 13 90 13 01 c6 90 13 90 13 89 f7 } //100
		$a_03_2 = {8b 34 24 83 c4 04 90 13 90 13 81 ee ?? ?? ?? ?? 90 13 90 13 01 c6 } //100
		$a_03_3 = {30 d0 aa e2 ?? 75 90 0a 0a 00 30 d0 aa 90 13 ac 90 13 30 d0 } //100
		$a_03_4 = {e8 00 00 00 00 90 13 83 c4 04 8b 74 24 fc 90 13 90 13 81 ee ?? ?? ?? ?? 90 13 90 13 01 c6 90 13 90 13 89 f7 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_03_3  & 1)*100+(#a_03_4  & 1)*100) >=201
 
}