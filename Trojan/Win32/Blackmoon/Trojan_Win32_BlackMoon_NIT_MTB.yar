
rule Trojan_Win32_BlackMoon_NIT_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {a1 04 d0 41 00 56 85 c0 be 04 d0 41 00 74 17 8b 0d 00 d0 41 00 6a 00 51 6a 01 ff d0 8b 46 04 83 c6 04 85 c0 } //2
		$a_01_1 = {44 65 6c 65 74 65 30 30 2e 62 61 74 } //1 Delete00.bat
		$a_01_2 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}