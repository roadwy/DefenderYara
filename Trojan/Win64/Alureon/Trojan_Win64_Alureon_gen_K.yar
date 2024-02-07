
rule Trojan_Win64_Alureon_gen_K{
	meta:
		description = "Trojan:Win64/Alureon.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 8b 74 24 08 44 8d 48 04 ba 00 00 10 00 33 c9 41 b8 00 30 00 00 bf 77 07 00 00 ff 15 } //01 00 
		$a_03_1 = {0f b7 40 16 44 8d 63 01 c1 e8 0d 41 23 c4 0f 84 90 01 04 ff cf 90 00 } //01 00 
		$a_01_2 = {72 00 65 00 73 00 74 00 61 00 72 00 74 00 36 00 34 00 } //00 00  restart64
	condition:
		any of ($a_*)
 
}