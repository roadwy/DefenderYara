
rule Trojan_Linux_Kaiji_A_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 65 74 63 2f 69 64 2e 73 65 72 76 69 63 65 73 2e 63 6f 6e 66 } //01 00 
		$a_00_1 = {6f 73 2f 75 73 65 72 2e 6c 6f 6f 6b 75 70 55 73 65 72 49 64 } //01 00 
		$a_00_2 = {2f 72 6f 6f 74 2f 73 72 63 2f 64 64 6f 73 2f 6b 69 6c 6c 2e 67 6f } //01 00 
		$a_00_3 = {64 64 6f 73 2e 67 65 74 49 70 46 72 6f 6d 41 64 64 72 } //01 00 
		$a_00_4 = {63 72 79 70 74 6f 2f 63 69 70 68 65 72 2e 4e 65 77 43 46 42 44 65 63 72 79 70 74 65 72 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}