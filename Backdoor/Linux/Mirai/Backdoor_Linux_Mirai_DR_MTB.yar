
rule Backdoor_Linux_Mirai_DR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 6f 62 2c 36 2d 33 23 2b 54 6a 6d 67 6c 74 70 23 4d 57 23 32 33 2d 33 38 23 54 4c 54 35 37 2a 23 42 73 73 6f 66 54 66 61 48 6a 77 2c 36 30 34 2d 30 35 23 2b 48 4b 57 4e 4f 2f 23 6f 6a 68 66 23 44 66 60 68 6c 2a 23 } //00 00 
	condition:
		any of ($a_*)
 
}