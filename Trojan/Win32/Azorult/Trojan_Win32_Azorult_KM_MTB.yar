
rule Trojan_Win32_Azorult_KM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 81 3d 90 01 04 9e 13 00 00 a3 90 01 04 75 90 01 01 33 c0 50 50 50 ff 15 90 01 04 81 05 90 01 04 c3 9e 26 00 0f b7 05 90 01 04 25 90 00 } //1
		$a_00_1 = {30 04 37 83 fb 19 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Azorult_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 25 ff 00 00 00 8a 98 90 01 04 89 0d 90 01 04 88 90 01 05 88 99 90 01 04 0f b6 88 90 01 04 0f b6 d3 90 00 } //1
		$a_02_1 = {8d 34 38 e8 90 01 04 30 06 b8 01 00 00 00 29 85 90 01 04 8b 85 90 01 04 85 c0 79 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}