
rule Ransom_Win32_Clop_PA_MTB{
	meta:
		description = "Ransom:Win32/Clop.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 c4 81 c2 67 55 ba 00 89 55 c4 8b 90 02 04 8b 90 02 04 8b 14 81 89 90 02 05 8b 45 c4 69 c0 00 c0 0f 00 89 45 c4 8b 0d 38 93 40 00 89 8d 90 02 04 8b 55 c4 81 ea 00 f0 ff 00 89 55 c4 8b 85 90 02 04 33 85 90 02 04 89 85 90 02 04 8b 4d c4 90 00 } //1
		$a_03_1 = {81 c1 00 a0 ba 0b 89 4d c4 c1 85 90 02 04 09 8b 55 c4 81 ea ab 5a 05 00 89 55 c4 8b 85 90 02 04 33 85 90 02 04 89 85 90 02 04 8b 4d c4 81 c1 ab 5a 15 00 89 4d c4 8b 95 90 02 04 2b 55 90 02 02 89 95 90 02 04 8b 45 c4 2d 00 f0 ff 0f 89 45 c4 8b 4d 90 02 02 8b 55 90 02 02 8b 85 90 02 04 89 04 8a e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}