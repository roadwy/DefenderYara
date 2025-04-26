
rule Trojan_Win32_Busky_J{
	meta:
		description = "Trojan:Win32/Busky.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 94 14 00 00 } //1
		$a_01_1 = {00 87 04 75 1f ef d0 11 98 88 00 60 97 de ac f9 } //1
		$a_00_2 = {81 7d fc 80 00 00 00 0f 8d } //1
		$a_01_3 = {61 56 31 39 44 00 } //1 噡㤱D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}