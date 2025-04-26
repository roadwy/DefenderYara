
rule Trojan_Win32_Alureon_DW{
	meta:
		description = "Trojan:Win32/Alureon.DW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 4d 08 3a c3 75 e6 3b f9 75 02 33 ff 3b fb 0f 84 ?? ?? ?? ?? 56 8d 85 ?? ?? ?? ?? 53 50 c6 45 ?? 6b } //1
		$a_03_1 = {68 51 c6 a6 02 e8 ?? ?? ?? ?? 85 c0 75 } //1
		$a_01_2 = {6b 6e 6f 63 6b 5f 25 64 5f 25 78 } //1 knock_%d_%x
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}