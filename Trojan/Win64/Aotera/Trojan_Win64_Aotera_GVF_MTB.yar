
rule Trojan_Win64_Aotera_GVF_MTB{
	meta:
		description = "Trojan:Win64/Aotera.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 4e d0 8b c1 f7 d8 44 8b c0 41 83 c8 01 45 0f bd d0 f3 45 0f bd c0 41 83 f0 1f f7 05 8a 5e 11 00 00 10 00 00 45 0f 45 d0 45 8b c2 49 c1 e0 03 4c 8d 15 80 7b 0d 00 4d 03 c2 49 03 00 48 c1 f8 20 3b d0 0f 4d c2 03 c6 41 3b 41 08 0f 8f f9 00 00 00 } //1
		$a_01_1 = {67 53 58 48 55 72 33 4f 63 48 39 38 47 4e 6b 58 5a 79 6a 47 6c 52 61 } //1 gSXHUr3OcH98GNkXZyjGlRa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}