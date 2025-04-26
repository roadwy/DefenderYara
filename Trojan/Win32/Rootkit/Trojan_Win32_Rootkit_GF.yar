
rule Trojan_Win32_Rootkit_GF{
	meta:
		description = "Trojan:Win32/Rootkit.GF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 04 01 00 00 68 05 01 00 00 8d 4d f8 } //1
		$a_01_1 = {68 3f 00 0f 00 6a 00 6a 00 ff 15 } //1
		$a_03_2 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 c0 8d 4d f4 e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc ff 75 50 } //1
		$a_00_3 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 68 00 69 00 64 00 65 00 2e 00 73 00 79 00 73 00 } //1 processhide.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}