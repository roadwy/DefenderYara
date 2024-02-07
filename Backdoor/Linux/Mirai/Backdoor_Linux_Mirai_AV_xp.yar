
rule Backdoor_Linux_Mirai_AV_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AV!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5b 68 74 74 70 20 66 6c 6f 6f 64 5d 20 68 65 61 64 65 72 } //01 00  [http flood] header
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00  npxXoudifFeEgGaACScs
		$a_00_2 = {b0 30 d7 e1 40 00 13 e3 1e 00 00 0a 38 40 87 e2 04 20 a0 e1 } //01 00 
		$a_00_3 = {4d 75 6c 74 69 68 6f 70 20 61 74 74 65 6d 70 74 65 64 } //01 00  Multihop attempted
		$a_00_4 = {06 30 d2 e7 37 30 23 e2 06 30 c2 e7 01 20 82 e2 07 00 52 e1 f9 ff ff 1a } //00 00 
	condition:
		any of ($a_*)
 
}