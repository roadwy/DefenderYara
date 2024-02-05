
rule Backdoor_Linux_Mirai_DQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 76 61 72 2f 43 6f 6e 64 69 42 6f 74 } //01 00 
		$a_00_1 = {2f 74 6d 70 2f 7a 78 63 72 39 39 39 39 } //01 00 
		$a_02_2 = {77 67 65 74 90 02 06 3a 2f 2f 63 64 6e 32 2e 64 75 63 33 6b 2e 63 6f 6d 2f 74 20 2d 4f 2d 7c 73 68 90 00 } //01 00 
		$a_00_3 = {50 4f 53 54 20 2f 63 67 69 2d 62 69 6e 2f 6c 75 63 69 2f } //00 00 
	condition:
		any of ($a_*)
 
}