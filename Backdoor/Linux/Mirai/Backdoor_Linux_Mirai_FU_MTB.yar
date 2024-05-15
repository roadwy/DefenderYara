
rule Backdoor_Linux_Mirai_FU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 56 00 00 4a ae 00 0c 67 0c 20 6e 00 08 10 28 00 40 4a 00 66 3e 4a ae 00 0c 66 16 20 6e 00 08 20 28 00 1c 2f 2e 00 08 2f 00 61 ff 00 00 38 1a 50 8f 20 6e 00 08 21 6e 00 0c 01 ba 4a ae 00 0c 66 12 20 6e 00 08 20 28 00 1c 2f 00 61 ff 00 00 37 0e 58 8f } //01 00 
		$a_00_1 = {42 80 10 10 d6 80 20 02 02 80 00 00 ff ff 42 42 48 42 d0 82 24 04 42 42 48 42 d4 83 02 84 00 00 ff ff d0 84 42 81 12 29 00 09 d4 81 42 81 32 05 d0 81 d0 82 22 00 42 41 48 41 4a 81 66 ae } //00 00 
	condition:
		any of ($a_*)
 
}