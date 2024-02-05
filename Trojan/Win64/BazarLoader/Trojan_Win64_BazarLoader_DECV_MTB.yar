
rule Trojan_Win64_BazarLoader_DECV_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DECV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 30 48 8d 84 08 08 01 00 00 48 89 44 24 40 48 8b 44 24 28 8b 40 50 41 b9 40 00 00 00 41 b8 00 30 00 00 8b d0 48 8b 44 24 28 48 8b 48 30 } //05 00 
		$a_01_1 = {44 6b c2 7c b9 17 00 00 00 c1 e2 05 8b c2 41 83 e8 2c 4c 0f af c0 49 8b c2 49 f7 e0 48 c1 ea 07 48 69 c2 ff 00 00 00 4c 2b c0 41 0f b6 c0 0f 45 c8 33 d2 41 88 0c 39 ff c2 81 fa f0 49 02 00 } //05 00 
		$a_01_2 = {41 c6 06 4d 8a 45 a9 34 d9 41 88 46 01 be 02 00 00 00 b1 37 bb 03 } //01 00 
		$a_81_3 = {45 6e 74 65 72 44 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}