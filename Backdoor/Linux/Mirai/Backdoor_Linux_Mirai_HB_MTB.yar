
rule Backdoor_Linux_Mirai_HB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {c2 00 a0 10 c2 24 20 10 82 10 20 08 c0 28 e0 0d c2 28 e0 0c c2 04 20 26 82 08 40 0c 82 10 40 0b 82 08 40 0d 82 10 40 0a c2 24 20 26 82 04 a0 1c 80 a1 20 00 c2 36 e0 02 fa 2e e0 01 82 38 00 14 ee 2e e0 08 02 80 00 04 c2 36 e0 04 03 00 00 10 c2 36 e0 06 82 10 20 11 } //01 00 
		$a_00_1 = {82 04 60 08 c2 36 a0 04 c2 17 bf ce c4 17 bf c6 c2 36 a0 02 c4 36 80 00 c2 07 bf f4 82 00 60 01 c2 27 bf f4 e0 07 bf f4 ac 0e 20 ff 92 10 20 04 80 a4 00 16 06 bf ff a2 90 10 25 e6 10 80 00 8c c0 27 bf f4 } //00 00 
	condition:
		any of ($a_*)
 
}