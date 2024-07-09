
rule Trojan_Win32_Graftor_HNA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {4e 0e 71 b5 bf 97 33 e1 3a de 7b 6a 19 80 2d 74 19 c9 f6 c2 83 8d 4c 49 0b e9 ?? ?? ?? ?? 53 48 45 4c 4c 33 32 2e 44 4c 4c 00 d2 c0 18 e0 b0 2e 68 51 89 e9 36 f9 f8 e9 f8 28 00 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}