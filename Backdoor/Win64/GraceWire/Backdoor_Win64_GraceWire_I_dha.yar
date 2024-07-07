
rule Backdoor_Win64_GraceWire_I_dha{
	meta:
		description = "Backdoor:Win64/GraceWire.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 fd 42 72 b6 48 89 b4 24 e0 00 00 00 48 89 bc 24 b8 00 00 00 4c 89 a4 24 b0 00 00 00 4c 89 b4 24 a8 00 00 00 89 bc 24 a0 00 00 00 e8 90 01 01 01 00 00 b9 c1 6d 68 ed 48 8b d8 e8 90 01 01 01 00 00 b9 21 3b df 50 48 8b f8 e8 90 01 01 01 00 b9 91 fd 47 59 48 8b f0 e8 90 01 01 01 00 00 b9 7f 28 a0 69 4c 8b e0 e8 90 01 01 01 00 00 b9 2f 44 d4 9b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}