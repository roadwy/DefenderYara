
rule Backdoor_Linux_Mirai_FB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 02 00 eb 00 08 a0 e1 07 10 a0 e1 20 08 a0 e1 e8 16 00 eb 00 08 a0 e1 20 3c a0 e1 07 30 c5 e5 8d 3e 8d e2 20 08 a0 e1 08 30 83 e2 04 20 86 e0 06 00 c5 e5 03 20 82 e0 d3 20 42 e2 03 10 d2 e5 02 30 d2 e5 01 34 83 e1 00 00 53 e1 } //02 00 
		$a_01_1 = {24 32 9f e5 03 30 91 e7 00 40 83 e5 2f 10 a0 e3 00 00 90 e5 5a 08 00 eb 10 32 9f e5 00 50 9d e5 00 00 50 e3 03 20 95 e7 01 30 80 12 00 00 82 e5 00 30 82 15 00 40 82 05 } //00 00 
	condition:
		any of ($a_*)
 
}