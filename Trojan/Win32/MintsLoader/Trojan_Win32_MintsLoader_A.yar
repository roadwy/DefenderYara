
rule Trojan_Win32_MintsLoader_A{
	meta:
		description = "Trojan:Win32/MintsLoader.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-08] 20 00 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 } //1
		$a_00_1 = {3d 00 27 00 75 00 72 00 27 00 } //1 ='ur'
		$a_00_2 = {6e 00 65 00 77 00 2d 00 61 00 6c 00 69 00 61 00 73 00 } //1 new-alias
		$a_00_3 = {2d 00 75 00 73 00 65 00 62 00 } //1 -useb
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}