
rule Trojan_Win32_Semsubim_A{
	meta:
		description = "Trojan:Win32/Semsubim.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 40 6a 05 56 c6 44 24 25 c0 c6 44 24 26 c2 c6 44 24 27 0c ff d3 8b 4c 24 14 32 c0 89 0e 88 46 04 } //1
		$a_03_1 = {c6 44 24 08 b8 50 6a 40 6a 08 56 c6 44 24 19 01 c6 44 24 1d c2 c6 44 24 1e 04 ff 15 90 01 04 8b 4c 24 08 8b 54 24 0c 89 0e 89 56 04 90 00 } //1
		$a_03_2 = {c1 fe 02 ff 15 90 01 04 33 d2 8b 4c 24 90 01 01 f7 f6 8b 14 91 52 8b 54 24 90 01 02 68 02 05 00 00 8b 42 20 50 ff d7 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}