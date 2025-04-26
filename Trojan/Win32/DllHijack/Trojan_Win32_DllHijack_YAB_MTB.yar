
rule Trojan_Win32_DllHijack_YAB_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 04 73 b0 f0 3c e8 c7 9f 00 00 89 34 24 c7 44 24 04 34 6d 62 47 a3 ?? ?? ?? ?? e8 b2 9f 00 00 89 34 24 c7 44 24 04 c7 7b 3a a4 } //1
		$a_01_1 = {44 69 72 65 63 74 33 44 43 72 65 61 74 65 38 } //1 Direct3DCreate8
		$a_01_2 = {8d 44 7d 00 03 42 24 0f b7 00 8d 44 85 00 03 42 1c 03 28 83 c4 08 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=12
 
}