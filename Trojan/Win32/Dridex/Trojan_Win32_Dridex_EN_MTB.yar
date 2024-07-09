
rule Trojan_Win32_Dridex_EN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 00 02 01 0b 01 00 00 00 40 03 00 } //2
		$a_01_1 = {03 0c 60 2a 00 07 4a 10 01 03 01 00 04 00 10 00 01 00 0c 00 02 01 0a 8c 01 70 01 00 00 07 0b 27 0e 12 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}
rule Trojan_Win32_Dridex_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {2b c8 8b 44 24 14 8b 3f 02 c7 89 7c 24 24 f6 d8 0f b6 fb 8a f8 89 4c 24 10 } //10
		$a_02_1 = {89 07 b0 ce 2a 44 24 0f 83 c7 04 2a 05 ?? ?? ?? ?? 2a 44 24 10 02 d8 89 7c 24 1c 83 6c 24 20 01 8b 44 24 14 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_EN_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.EN!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 0b 83 c3 04 0f b6 c8 66 83 c1 49 89 5c 24 14 66 03 4c 24 28 83 6c 24 20 01 66 8b f9 89 7c 24 10 } //10
		$a_01_1 = {04 17 02 c0 02 c3 02 c1 02 c0 eb 07 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}