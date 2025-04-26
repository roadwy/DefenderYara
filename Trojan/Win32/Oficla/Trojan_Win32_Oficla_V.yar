
rule Trojan_Win32_Oficla_V{
	meta:
		description = "Trojan:Win32/Oficla.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 ec 44 c6 45 ?? 25 c6 45 ?? (75|78) c6 45 ?? 25 c6 45 ?? (75|78) c6 45 ?? 00 } //1
		$a_01_1 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 } //1
		$a_03_2 = {0d 00 00 00 80 ba ff e8 a4 35 89 d1 31 d2 f7 f1 81 c2 00 e1 f5 05 c6 45 ?? 25 c6 45 ?? 64 c6 45 ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}