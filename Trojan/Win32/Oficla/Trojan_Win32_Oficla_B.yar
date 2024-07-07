
rule Trojan_Win32_Oficla_B{
	meta:
		description = "Trojan:Win32/Oficla.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 83 c3 01 83 c2 01 0f b6 c0 01 f0 88 01 83 c1 01 39 fb 75 e9 } //1
		$a_01_1 = {81 e2 8c 00 00 00 89 95 d0 9d ff ff e9 84 00 00 00 } //1
		$a_01_2 = {8b 8d d0 9d ff ff 0f b6 c0 31 c8 89 f1 89 85 80 9d ff ff 8b 85 c4 9d ff ff d3 e0 83 f8 3f 7f 9f } //1
		$a_03_3 = {c7 44 24 04 ce fe a3 73 c7 04 24 37 09 84 36 e8 90 01 04 8d 95 90 01 04 a3 90 01 04 89 14 24 ff d0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}