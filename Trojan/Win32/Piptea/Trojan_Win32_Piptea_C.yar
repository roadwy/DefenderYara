
rule Trojan_Win32_Piptea_C{
	meta:
		description = "Trojan:Win32/Piptea.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {b9 79 37 9e 90 09 03 00 c7 45 } //1
		$a_01_1 = {55 54 5d 64 a1 18 00 00 00 5d c3 } //1
		$a_03_2 = {0f b6 40 02 85 c0 74 ?? e9 } //1
		$a_01_3 = {03 48 28 89 4d d0 ff 55 d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}