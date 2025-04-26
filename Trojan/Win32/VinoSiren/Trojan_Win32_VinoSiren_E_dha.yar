
rule Trojan_Win32_VinoSiren_E_dha{
	meta:
		description = "Trojan:Win32/VinoSiren.E!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 eb 08 89 5c 24 2c 8b d1 8b d9 c1 ea 08 c1 eb 10 22 da 22 d9 8b c8 c1 e9 10 22 4c 24 2c 89 54 24 14 32 d9 8a d0 22 54 24 28 c1 e8 18 32 da 32 d8 8b 44 24 10 8d 0c 3f 33 cf 81 e1 fe 01 00 00 c1 e0 18 0b 44 24 2c c1 e1 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}