
rule Trojan_Win32_Waltrodock_C{
	meta:
		description = "Trojan:Win32/Waltrodock.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 75 72 6c 25 64 } //1 softurl%d
		$a_03_1 = {5c 56 65 72 73 69 6f 6e 4b 65 79 2e 69 6e 69 90 02 0c 66 75 63 6b 90 00 } //1
		$a_03_2 = {32 da 40 83 f8 10 88 90 02 06 75 02 33 c0 41 81 f9 04 01 00 00 7c 90 00 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*4) >=5
 
}