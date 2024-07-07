
rule Trojan_Win32_Uitlotex_A{
	meta:
		description = "Trojan:Win32/Uitlotex.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 53 8d 63 6e 9c a7 1a c6 dd 39 4e 35 8d ba 72 9c 6b 1b 74 e5 38 d6 } //1
		$a_01_1 = {a7 29 c6 b1 b7 4e 53 8d 63 6e 9c a7 1a c6 dd 39 4e 35 8d ba 72 9c 6b } //1
		$a_01_2 = {e5 4e 58 d7 df 8e df 5b f9 53 96 35 f7 e3 b7 d6 fe 54 e5 8d 7d f8 ed } //1
		$a_01_3 = {5b ea 32 fe 0e 7c 72 d7 d7 74 fb bc 6a ff 00 24 8f c9 cb f0 61 f0 9a } //1
		$a_03_4 = {7e 33 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 46 e8 90 01 04 8b 55 f4 8d 45 f8 e8 90 01 04 8b c7 8b 55 f8 e8 90 01 04 43 4e 75 d2 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}