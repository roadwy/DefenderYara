
rule Trojan_Win32_Netnam_B{
	meta:
		description = "Trojan:Win32/Netnam.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 69 62 65 72 61 74 65 00 } //1
		$a_01_1 = {54 31 59 39 34 33 6a 49 68 6b 00 } //1
		$a_01_2 = {8b 81 0c 01 00 00 66 8b 4c 24 04 66 89 08 c2 04 00 } //1
		$a_03_3 = {f7 b1 04 01 00 00 8a 04 3e 8a 14 0a 3a c2 74 09 84 c0 74 05 32 c2 88 04 90 04 01 01 3e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}