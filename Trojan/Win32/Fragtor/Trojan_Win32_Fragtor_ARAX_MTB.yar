
rule Trojan_Win32_Fragtor_ARAX_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 c2 0f b7 05 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 66 0f ac c1 ?? 89 c8 35 ?? ?? ?? ?? 66 89 46 18 89 d1 } //2
		$a_01_1 = {47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 57 } //2 GetFileVersionInfoW
		$a_01_2 = {47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 53 69 7a 65 57 } //2 GetFileVersionInfoSizeW
		$a_01_3 = {56 65 72 51 75 65 72 79 56 61 6c 75 65 57 } //2 VerQueryValueW
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}