
rule Backdoor_Linux_Mirai_Ab_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Ab!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 45 54 20 2f 73 68 65 6c 6c 3f 63 64 2b 2f 74 6d 70 3b 72 6d 2b 2d 72 66 } //01 00 
		$a_02_1 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 90 02 20 2d 6c 20 2f 74 6d 70 2f 62 69 67 48 20 2d 72 90 00 } //01 00 
		$a_00_2 = {2f 62 65 61 73 74 6d 6f 64 65 2f 62 33 61 73 74 6d 6f 64 65 2e 6d 69 70 73 3b 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 62 69 67 48 } //00 00 
	condition:
		any of ($a_*)
 
}