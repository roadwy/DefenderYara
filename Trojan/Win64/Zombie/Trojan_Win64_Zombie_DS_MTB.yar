
rule Trojan_Win64_Zombie_DS_MTB{
	meta:
		description = "Trojan:Win64/Zombie.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 20 64 65 6c 20 00 43 4f 4d 53 50 45 43 00 72 62 00 00 5f 2e 65 78 65 } //01 00 
		$a_01_1 = {5a 6f 6d 62 69 65 2e 65 78 65 } //01 00 
		$a_01_2 = {63 66 64 69 73 6b 2e 65 78 65 } //01 00 
		$a_01_3 = {cf eb d5 d2 bb d8 ce c4 bc fe 2d 5f 2d 00 00 20 20 c1 aa cf b5 d7 f7 d5 df 20 bb d6 b8 b4 cb f9 d3 d0 ce c4 bc fe } //01 00 
		$a_01_4 = {90 41 57 41 56 41 55 41 54 55 57 56 53 48 83 ec 38 31 d2 48 89 cf e8 f6 fd ff ff 48 89 c5 f6 47 50 01 0f 84 c9 00 00 00 48 8b 77 28 48 85 f6 0f 84 dc } //00 00 
	condition:
		any of ($a_*)
 
}