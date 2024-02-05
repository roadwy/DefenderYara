
rule Backdoor_Linux_BPFDoor_F_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 31 c9 45 31 c0 31 c9 ba 00 00 01 00 48 89 de 89 ef e8 99 fd ff ff 85 c0 } //01 00 
		$a_01_1 = {2f 76 61 72 2f 72 75 6e 2f 69 6e 69 74 64 2e 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}