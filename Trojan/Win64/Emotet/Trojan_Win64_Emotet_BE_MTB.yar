
rule Trojan_Win64_Emotet_BE_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 d0 8b c3 ff c3 6b d2 90 01 01 2b c2 48 63 d0 48 8b 05 90 01 04 8a 14 02 41 32 90 02 04 88 17 48 ff c7 49 90 02 04 75 90 00 } //01 00 
		$a_03_1 = {ff c8 83 c8 90 01 01 ff c0 48 63 d0 48 8b 05 90 01 04 ff c6 8a 14 02 41 32 14 1e 88 13 48 ff c3 49 ff cd 75 90 00 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_BE_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 32 4c 11 90 01 01 b8 90 01 04 41 88 4a 90 01 01 41 8d 48 90 01 01 f7 e9 8b cf c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 8b 05 90 01 04 ff c1 48 63 c9 0f b6 0c 01 b8 bf 3c b6 22 42 32 4c 16 90 01 01 41 88 4a 90 00 } //01 00 
		$a_03_1 = {f7 f9 48 63 ca 48 8b 05 90 01 04 0f b6 04 08 41 8b d0 33 d0 8b 4c 24 90 01 01 8b 84 24 90 01 04 03 c1 2b 44 24 90 01 01 2b 44 24 90 01 01 03 44 24 90 01 01 48 63 c8 48 8b 84 24 90 01 04 88 14 08 e9 90 00 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}