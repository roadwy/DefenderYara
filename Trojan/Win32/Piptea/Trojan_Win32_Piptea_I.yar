
rule Trojan_Win32_Piptea_I{
	meta:
		description = "Trojan:Win32/Piptea.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 87 b0 00 00 00 8b 8f ac 00 00 00 8b 04 01 89 87 b0 00 00 00 8b d0 a1 90 01 04 89 87 a8 00 00 00 c1 e2 10 c1 e8 10 0b c2 90 00 } //1
		$a_01_1 = {80 3a 90 74 01 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}