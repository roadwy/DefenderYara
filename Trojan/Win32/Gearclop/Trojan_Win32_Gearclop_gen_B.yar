
rule Trojan_Win32_Gearclop_gen_B{
	meta:
		description = "Trojan:Win32/Gearclop.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 ad 86 c4 66 33 05 90 01 02 40 00 66 ff 05 90 01 02 40 00 66 ab e2 ea b8 e8 00 00 00 50 6a 40 ff 54 24 24 85 c0 0f 84 f8 00 00 00 be 02 11 40 00 8b f8 b9 e8 00 00 00 f3 a4 ff e0 8b 3c 24 03 7f 3c 8b f7 8b 7f 34 8b 76 50 03 f7 57 8b 44 24 08 ff d0 68 00 80 00 00 6a 00 57 8b 44 24 14 ff d0 6a 40 68 00 30 00 00 68 00 00 01 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}