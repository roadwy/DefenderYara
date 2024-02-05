
rule Backdoor_Linux_Shellshock_A{
	meta:
		description = "Backdoor:Linux/Shellshock.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4a 55 4e 4b 20 46 6c 6f 6f 64 69 6e 67 20 25 73 3a 25 64 20 66 6f 72 20 25 64 20 73 65 63 6f 6e 64 73 2e 00 } //01 00 
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 3b 65 63 68 6f 20 2d 65 20 27 5c 31 34 37 5c 31 34 31 5c 31 37 31 5c 31 34 36 5c 31 34 37 5c 31 36 34 27 } //01 00 
		$a_00_2 = {67 61 79 66 67 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}