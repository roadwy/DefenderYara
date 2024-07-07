
rule Worm_Win32_Sawemp_A{
	meta:
		description = "Worm:Win32/Sawemp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 00 65 00 73 00 65 00 6e 00 65 00 5f 00 73 00 65 00 6e 00 67 00 5f 00 67 00 61 00 77 00 65 00 2e 00 68 00 74 00 6d 00 } //1 pesene_seng_gawe.htm
		$a_01_1 = {56 00 42 00 57 00 47 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 } //1 VBWG Infected
		$a_01_2 = {4b 65 62 65 6e 61 72 61 6e } //1 Kebenaran
		$a_01_3 = {62 79 3a 20 72 69 65 79 73 68 61 3c 2f 70 3e } //1 by: rieysha</p>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}