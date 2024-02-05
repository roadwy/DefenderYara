
rule Backdoor_Linux_Tusnami_C_MTB{
	meta:
		description = "Backdoor:Linux/Tusnami.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 61 6e 64 65 6d 6f 20 73 68 69 72 61 6e 61 69 20 77 61 20 79 6f } //01 00 
		$a_00_1 = {68 69 74 74 65 72 75 20 6b 6f 74 6f 20 64 61 6b 65 } //01 00 
		$a_02_2 = {41 6c 72 65 61 64 79 90 02 02 6e 69 6e 67 2e 90 00 } //01 00 
		$a_00_3 = {3a 4b 49 4c 4c 5f 50 4f 52 54 } //00 00 
	condition:
		any of ($a_*)
 
}