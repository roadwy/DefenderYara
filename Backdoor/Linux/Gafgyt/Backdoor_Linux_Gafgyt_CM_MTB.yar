
rule Backdoor_Linux_Gafgyt_CM_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {10 2d 80 42 00 00 a0 82 00 00 8f c2 00 08 24 42 00 01 af c2 00 08 8f c2 00 08 8f c3 00 00 00 62 10 2a 10 40 ff ed 00 00 00 00 8f c3 00 08 } //1
		$a_00_1 = {10 2d 00 e0 18 2d 00 02 10 00 af c2 00 10 00 03 10 00 af c2 00 14 ff c0 00 30 24 02 00 20 ff c2 00 28 8f c2 00 10 18 40 00 23 00 00 00 00 ff c0 00 20 df c3 00 08 ff c3 00 18 10 00 00 08 00 00 00 00 df c3 00 20 24 62 00 01 00 40 18 2d ff c3 00 20 df c2 00 18 64 42 00 01 ff c2 00 18 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}