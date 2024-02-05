
rule Backdoor_Linux_NetBus_A_xp{
	meta:
		description = "Backdoor:Linux/NetBus.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b bd fc fb ff ff 31 c0 fc b9 ff ff ff ff f2 ae 89 ca f7 d2 4a } //01 00 
		$a_00_1 = {8a 13 84 d2 74 09 43 47 8a 13 80 fa 0a 75 f1 } //01 00 
		$a_00_2 = {8b bd dc fd ff ff 80 3f 2f 75 01 47 57 } //01 00 
		$a_00_3 = {31 c0 fc b9 7f 00 00 00 f3 ab 66 ab aa 89 df } //00 00 
	condition:
		any of ($a_*)
 
}