
rule Backdoor_Linux_Mirai_EC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {34 97 69 88 78 c0 00 00 34 82 63 82 00 00 00 00 34 84 76 83 77 86 75 8a 00 00 00 00 34 81 7f c8 00 00 00 00 34 97 69 88 78 c0 68 8a 77 71 34 72 63 6a 00 00 34 97 69 88 78 c0 75 8a 6f 38 6f 74 6b 00 00 00 68 88 78 8c 7e 9b 21 b4 00 00 00 00 2b d7 2b d7 2b df 2b df 00 00 00 00 35 94 74 00 34 8a 7a 97 68 00 00 00 34 83 7e 91 34 9a 69 8e 75 73 74 7a 00 00 00 00 49 d0 68 b7 6a d6 4f dd } //00 00 
	condition:
		any of ($a_*)
 
}