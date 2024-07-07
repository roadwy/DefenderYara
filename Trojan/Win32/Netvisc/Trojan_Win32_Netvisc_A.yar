
rule Trojan_Win32_Netvisc_A{
	meta:
		description = "Trojan:Win32/Netvisc.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 53 4f 43 4b 5f 63 6f 6e 6e 65 63 74 20 4f 4b 21 00 } //1 卮䍏彋潣湮捥⁴䭏!
		$a_01_1 = {2e 6d 79 66 77 2e 75 73 00 } //1
		$a_00_2 = {c6 85 60 df ff ff 2f c6 85 61 df ff ff 54 c6 85 62 df ff ff 41 c6 85 63 df ff ff 53 c6 85 64 df ff ff 4b c6 85 65 df ff ff 4b c6 85 66 df ff ff 49 c6 85 67 df ff ff 4c c6 85 68 df ff ff 4c } //1
		$a_02_3 = {53 56 57 c6 85 90 01 04 55 c6 85 90 01 04 4e c6 85 90 01 04 4b c6 85 90 01 04 4e c6 85 90 01 04 4f c6 85 90 01 04 57 c6 85 90 01 04 4e c6 85 90 01 04 20 90 00 } //1
		$a_00_4 = {c6 44 24 04 54 c6 44 24 05 6e c6 44 24 06 65 c6 44 24 07 74 c6 44 24 08 73 c6 44 24 09 76 c6 44 24 0a 63 88 44 24 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}