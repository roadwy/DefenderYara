
rule Trojan_Win32_VinoSiren_F_dha{
	meta:
		description = "Trojan:Win32/VinoSiren.F!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 18 33 d0 8b 4d f8 c1 e9 08 23 4d f8 8b 45 f8 c1 e8 10 23 c8 33 d1 88 55 f7 8b 4d f8 c1 e9 08 8b 55 fc d1 ea 33 55 fc 81 e2 ff 00 00 00 c1 e2 17 0b ca 89 4d 14 8b 45 f8 c1 e0 18 8b 4d fc c1 e9 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}