
rule Backdoor_Linux_Iroffer_A_xp{
	meta:
		description = "Backdoor:Linux/Iroffer.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 5d 08 8b 75 0c e8 74 c5 00 00 83 c4 f8 56 53 e8 92 00 00 00 83 c4 10 83 f8 01 74 0e 7e 4e 83 f8 02 74 3a 83 f8 03 } //1
		$a_00_1 = {83 c4 f8 ff 36 68 40 01 07 08 e8 05 60 ff ff 83 c4 f4 6a 00 } //1
		$a_00_2 = {a1 90 9c 07 08 31 c9 29 c3 39 d9 7d 1f bf 54 a5 07 08 8d 14 86 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}