
rule Trojan_Win32_Alureon_BD{
	meta:
		description = "Trojan:Win32/Alureon.BD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {59 6a 0a bf ?? ?? ?? ?? 8b f3 59 33 c0 f3 a6 0f 84 } //1
		$a_01_1 = {c6 45 f0 e9 ab 56 e8 } //1
		$a_01_2 = {59 59 74 12 83 c6 04 83 fe 04 72 e5 } //1
		$a_01_3 = {74 64 6c 6d 61 73 6b 2e 64 6c 6c } //1 tdlmask.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}