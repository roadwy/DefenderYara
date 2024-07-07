
rule Worm_Win32_Koobface_AP{
	meta:
		description = "Worm:Win32/Koobface.AP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {f5 f8 00 00 00 aa f4 28 6b 90 01 02 b1 90 00 } //1
		$a_01_1 = {f3 b8 00 fc 0d } //1
		$a_01_2 = {f5 07 00 01 00 } //1
		$a_00_3 = {43 00 3a 00 5c 00 4e 00 75 00 41 00 54 00 2e 00 76 00 62 00 70 00 } //1 C:\NuAT.vbp
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}