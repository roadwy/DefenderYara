
rule Trojan_Win32_Matsnu_O{
	meta:
		description = "Trojan:Win32/Matsnu.O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 41 49 4e 25 30 38 58 4d 55 54 45 58 } //1 MAIN%08XMUTEX
		$a_01_1 = {e8 05 00 00 00 2e 64 6c 6c 00 8d 95 f0 fe ff ff 52 ff 93 } //1
		$a_01_2 = {e8 0a 00 00 00 2f 25 73 3a 2a 2d 2d 25 73 00 } //1
		$a_01_3 = {30 d0 31 c9 b1 08 d3 ea f8 d1 d8 73 05 35 20 83 b8 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}