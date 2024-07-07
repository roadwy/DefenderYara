
rule Trojan_Win32_Dooxud_A{
	meta:
		description = "Trojan:Win32/Dooxud.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 80 c2 61 88 54 34 04 46 83 fe 05 7c e6 } //1
		$a_01_1 = {6a 04 68 00 30 00 00 8b f0 51 6a 00 56 ff d3 8b 54 24 14 8b f8 8b 44 24 18 6a 00 52 50 57 56 } //1
		$a_01_2 = {45 52 52 00 32 4b 38 00 57 4e 37 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}