
rule Trojan_Win64_Solorigate_SB_dha{
	meta:
		description = "Trojan:Win64/Solorigate.SB!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a c2 c0 e0 02 8d 0c 10 02 c9 44 2a 90 01 01 41 80 90 01 01 30 46 88 90 02 03 41 ff 90 01 01 4c 8b 90 02 02 83 fa 0a 90 00 } //01 00 
		$a_01_1 = {44 8b 0b 48 8d 5b 04 41 8b c1 48 c1 e8 10 0f b6 c8 41 8b c1 48 c1 e8 08 } //02 00 
		$a_03_2 = {48 8b cb 80 31 90 01 01 48 ff c1 48 8b 95 c0 00 00 00 48 8b c1 48 2b c3 48 3b c2 72 e8 90 00 } //02 00 
		$a_03_3 = {b8 89 88 88 88 f7 ef c7 44 90 01 02 00 00 00 01 4d 8b cc 03 d7 90 00 } //02 00 
		$a_02_4 = {37 2d 7a 69 70 2e 64 6c 6c 00 44 6c 6c 90 02 60 2e 54 6b 53 65 6c 50 72 6f 70 50 72 6f 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}