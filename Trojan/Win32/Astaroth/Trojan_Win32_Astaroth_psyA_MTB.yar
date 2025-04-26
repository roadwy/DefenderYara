
rule Trojan_Win32_Astaroth_psyA_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 42 ae bf 21 06 cf d1 72 06 cf d1 72 06 cf d1 72 b2 53 20 72 15 cf d1 72 b2 53 22 72 a1 cf d1 72 b2 53 23 72 18 cf d1 72 0f b7 55 72 07 cf d1 72 98 6f 16 72 04 cf d1 72 ab 91 d2 73 1c cf d1 72 ab 91 d4 73 3c cf d1 72 ab 91 d5 73 24 cf d1 [0-30] 2e 72 07 cf d1 72 b3 91 d3 73 07 cf d1 72 52 69 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}