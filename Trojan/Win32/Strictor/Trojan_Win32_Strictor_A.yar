
rule Trojan_Win32_Strictor_A{
	meta:
		description = "Trojan:Win32/Strictor.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c a1 28 c0 42 00 33 c5 89 45 fc 8b 55 08 8d 45 f4 56 8b f1 89 55 f4 8d 4e 04 c6 45 f8 01 51 0f 57 c0 c7 06 24 e2 41 00 50 66 0f d6 01 e8 ba 5b 00 00 8b 4d fc 83 c4 08 8b c6 33 cd 5e e8 2e 4a 00 00 8b e5 5d c2 04 00 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}