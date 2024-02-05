
rule Backdoor_Win32_Shiz_DF_MTB{
	meta:
		description = "Backdoor:Win32/Shiz.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 08 8d 14 0e 33 c9 8a cc 32 0a 88 0a 66 0f b6 c9 03 c8 b8 bf 58 00 00 69 c9 93 31 00 00 2b c1 46 3b 74 24 0c 72 d7 } //01 00 
		$a_01_1 = {8b 44 24 0c 33 db 8a de 8d 0c 06 8a 04 06 32 d8 66 0f b6 c0 03 c2 ba bf 58 00 00 69 c0 93 31 00 00 2b d0 46 3b 74 24 10 88 19 72 d4 } //00 00 
	condition:
		any of ($a_*)
 
}