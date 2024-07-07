
rule Trojan_Win32_Perkesh_gen_A{
	meta:
		description = "Trojan:Win32/Perkesh.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 0d 3d 02 01 00 00 75 57 83 7e 08 0d 75 51 57 6a 40 59 c6 85 fc fe ff ff 00 33 c0 8d bd fd fe ff ff } //1
		$a_01_1 = {bf a8 b0 cd cb b9 bb f9 00 } //1
		$a_00_2 = {00 4e 4f 44 33 32 00 00 } //1
		$a_00_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 00 55 53 45 52 33 32 2e 64 6c 6c } //1 敓坴湩潤獷潈歯硅A单剅㈳搮汬
		$a_00_4 = {63 61 6c 6c 6e 65 78 74 68 6f 6f 6b 65 78 } //1 callnexthookex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}