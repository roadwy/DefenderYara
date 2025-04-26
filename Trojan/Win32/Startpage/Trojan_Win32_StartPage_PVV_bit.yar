
rule Trojan_Win32_StartPage_PVV_bit{
	meta:
		description = "Trojan:Win32/StartPage.PVV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {c7 45 a0 33 36 30 54 c7 45 a4 72 61 79 2e } //1
		$a_00_1 = {c7 45 b0 51 51 50 43 c7 45 b4 54 72 61 79 } //1
		$a_03_2 = {8a 94 0d fc fe ff ff 30 ?? ?? ?? ?? ?? 41 81 f9 00 01 00 00 7c 02 33 c9 40 3d ?? ?? ?? ?? 7c e0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}