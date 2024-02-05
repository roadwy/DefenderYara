
rule Trojan_Linux_Bigviktor_A_MTB{
	meta:
		description = "Trojan:Linux/Bigviktor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 74 70 40 65 78 61 6d 70 6c 65 2e 63 6f 6d } //01 00 
		$a_00_1 = {25 73 2f 73 2e 6a 70 65 67 } //01 00 
		$a_00_2 = {2f 6d 61 6c 65 2e 6a 70 65 67 } //01 00 
		$a_00_3 = {25 73 2f 69 6d 61 67 65 2e 6a 70 65 67 3f 74 3d 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 26 76 3d 25 64 } //01 00 
		$a_00_4 = {31 2e 31 2e 31 2e 31 2c 38 2e 38 2e 38 2e 38 } //00 00 
	condition:
		any of ($a_*)
 
}