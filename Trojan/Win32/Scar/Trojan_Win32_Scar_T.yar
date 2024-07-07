
rule Trojan_Win32_Scar_T{
	meta:
		description = "Trojan:Win32/Scar.T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c2 08 00 60 68 de c0 de 00 68 90 01 04 e8 90 01 04 b8 aa 00 00 00 bb 02 00 00 00 53 50 6a 00 e8 90 01 04 a3 90 01 04 e8 90 01 04 61 c3 55 8b ec 83 c4 ec 90 00 } //1
		$a_03_1 = {05 01 01 01 01 51 90 90 8a c8 90 90 d3 c0 90 90 59 90 90 eb 10 90 00 } //1
		$a_03_2 = {e2 bb 59 8b 1d 90 01 02 00 0d ac 90 90 32 c3 90 90 aa f7 c1 01 00 00 00 74 90 00 } //1
		$a_00_3 = {53 68 61 64 6f 77 6c 69 6e 65 20 76 61 72 69 61 6e 74 } //1 Shadowline variant
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}