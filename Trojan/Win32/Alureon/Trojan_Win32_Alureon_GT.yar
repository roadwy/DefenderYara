
rule Trojan_Win32_Alureon_GT{
	meta:
		description = "Trojan:Win32/Alureon.GT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 3c 3c 22 00 56 89 5c 24 ?? ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 8d 84 24 ?? ?? 00 00 50 68 02 00 00 80 } //1
		$a_01_1 = {b8 48 46 00 00 66 89 07 b8 fa 01 00 00 3b c8 77 05 } //1
		$a_03_2 = {6a 01 6a 28 56 8b c7 e8 ?? ?? ?? ?? 85 c0 74 ad 33 ff 81 bd ?? ?? ff ff 78 56 34 12 74 0e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}