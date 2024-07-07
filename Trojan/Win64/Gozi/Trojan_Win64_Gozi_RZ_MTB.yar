
rule Trojan_Win64_Gozi_RZ_MTB{
	meta:
		description = "Trojan:Win64/Gozi.RZ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 57 f0 0f 57 f8 0f 28 de 0f 28 cf 41 0f 14 cb 44 0f 57 c0 0f 57 e8 0f 57 e0 41 0f 14 d8 41 0f 28 c3 0f 14 d9 0f 14 d4 0f 28 cd 0f 14 c8 0f 29 58 d0 } //1
		$a_01_1 = {50 68 79 73 58 33 5f 78 36 34 2e 70 64 62 } //1 PhysX3_x64.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}