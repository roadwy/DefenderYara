
rule Trojan_Win32_Sirefef_AN{
	meta:
		description = "Trojan:Win32/Sirefef.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 64 69 73 63 74 ?? 3d 73 65 6e 64 } //1
		$a_01_1 = {33 c0 89 06 89 46 04 89 46 08 89 46 0c 89 46 10 89 46 18 c7 46 1c 63 6e 63 74 } //1
		$a_01_2 = {26 61 69 64 3d 25 75 } //1 &aid=%u
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Sirefef_AN_2{
	meta:
		description = "Trojan:Win32/Sirefef.AN,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 64 69 73 63 74 ?? 3d 73 65 6e 64 } //1
		$a_01_1 = {33 c0 89 06 89 46 04 89 46 08 89 46 0c 89 46 10 89 46 18 c7 46 1c 63 6e 63 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}