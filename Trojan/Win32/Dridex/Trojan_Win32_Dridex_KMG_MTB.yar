
rule Trojan_Win32_Dridex_KMG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 89 15 90 01 04 8b 44 24 90 01 01 80 c3 16 89 35 90 01 04 0f b7 c9 8b 84 28 90 01 04 89 44 24 90 01 01 88 1d 90 01 04 81 ff d0 00 00 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ca 0f b6 05 90 01 04 3b f0 74 90 01 01 28 99 90 01 04 b8 a5 ff 00 00 2b c7 2b c6 8b f8 49 83 f9 01 7f 90 00 } //1
		$a_02_1 = {8a eb 39 05 90 01 04 74 90 01 01 28 9a 90 01 04 b0 a5 2a 05 90 01 04 2a c1 8a c8 4a 83 fa 01 7f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}