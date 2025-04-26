
rule Trojan_Win32_Busky_I{
	meta:
		description = "Trojan:Win32/Busky.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 94 14 00 00 (90 13|) [0-11] e8 ?? ?? ?? ?? 68 ?? ?? ?? 00 68 ?? ?? ?? 00 c3 } //1
		$a_01_1 = {00 87 04 75 1f ef d0 11 98 88 00 60 97 de ac f9 } //1
		$a_01_2 = {61 56 31 39 44 00 } //1 噡㤱D
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}