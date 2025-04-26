
rule Backdoor_Linux_Gafgyt_BP_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {c2 07 a0 48 c2 08 40 00 82 08 60 ff 80 a0 60 64 [0-10] c4 07 a0 4c 82 10 00 02 c6 00 40 00 82 00 a0 04 c2 27 a0 4c 82 10 20 61 c2 23 a0 5c d0 07 a0 44 92 10 00 03 94 10 20 0a 96 10 20 01 d8 07 bf e0 da 07 bf e4 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}