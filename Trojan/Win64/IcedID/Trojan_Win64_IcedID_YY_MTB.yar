
rule Trojan_Win64_IcedID_YY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {0f b7 44 24 24 66 ff c0 66 89 44 24 24 0f b7 44 24 24 0f b7 4c 24 28 3b c1 7d 90 01 01 0f b7 44 24 24 48 8b 4c 24 40 8a 04 01 88 44 24 20 8b 4c 24 2c e8 90 01 04 89 44 24 2c 0f b6 44 24 20 0f b6 4c 24 2c 33 c1 0f b7 4c 24 24 48 8b 54 24 48 88 04 0a 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 0f 50 06 80 5c 23 00 00 10 50 06 80 00 00 01 00 04 00 0d 00 88 21 44 6f 6e 6c 6f 62 6c 69 62 2e 41 00 00 01 40 05 82 5c 00 04 00 67 16 00 00 c9 0d 8e 66 47 fe 89 53 9b a0 10 1e 00 de 07 00 00 20 eb 90 b1 06 5d 04 00 00 10 50 06 80 5c 25 00 00 11 50 06 80 00 00 01 00 08 00 0f 00 ac 21 4d } //69 64 
	condition:
		any of ($a_*)
 
}