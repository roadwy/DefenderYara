
rule Backdoor_Linux_Mirai_EZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {10 c0 00 09 00 80 10 21 00 86 30 21 90 a2 00 00 00 00 00 00 a0 82 00 00 24 84 00 01 14 86 ff fb 24 a5 00 01 00 80 10 21 03 e0 00 08 } //01 00 
		$a_01_1 = {77 61 62 6a 74 61 6d } //01 00  wabjtam
		$a_01_2 = {62 65 61 72 64 72 6f 70 70 65 72 } //01 00  beardropper
		$a_01_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //00 00  /bin/busybox
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Mirai_EZ_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.EZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {18 d0 4d e2 ba 02 00 eb 00 c0 dd e5 0e 00 5c e3 90 01 04 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3 ab b1 a0 e1 1c cb a0 e1 0d b0 a0 e1 3a cd 8c e2 0c d0 4d e0 00 c0 93 e5 08 30 8d e5 04 c0 8d e5 00 20 8d e5 0c 30 8d e2 00 c0 a0 e3 90 00 } //01 00 
		$a_01_1 = {01 20 52 e2 58 50 9d e5 00 30 a0 03 01 30 a0 13 01 b0 8b e2 05 00 5b e1 00 30 a0 23 01 30 03 32 01 70 d4 e4 00 00 53 e3 01 70 cc e4 } //00 00 
	condition:
		any of ($a_*)
 
}