
rule Ransom_Win64_Cyclops_PBA_MTB{
	meta:
		description = "Ransom:Win64/Cyclops.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 10 01 ea 83 c2 ?? 0f b7 d2 89 d3 c1 eb 0f c1 ea 06 01 da 89 d3 c1 e3 07 29 da 01 ea 83 c2 ?? 80 c2 7f 0f b6 d2 8d 2c 52 c1 ed 08 89 d3 40 28 eb d0 eb 40 00 eb c0 eb 06 0f b6 db 89 dd c1 e5 07 29 dd 40 28 ea } //2
		$a_03_1 = {0f b7 c9 89 cb c1 eb 0f c1 e9 06 01 d9 89 cb c1 e3 07 29 d9 01 d1 81 c1 ?? ?? ?? ?? 80 c1 7f 0f b6 c9 8d 14 49 c1 ea 08 89 cb 28 d3 d0 eb 00 d3 c0 eb 06 0f b6 db 89 da c1 e2 07 29 da 28 d1 88 8c 04 } //1
		$a_01_2 = {63 79 63 6c 6f 70 73 } //1 cyclops
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}