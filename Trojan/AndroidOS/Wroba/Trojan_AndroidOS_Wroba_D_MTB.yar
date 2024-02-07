
rule Trojan_AndroidOS_Wroba_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Wroba.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 65 65 70 41 6c 69 76 65 00 74 72 79 20 74 6f 20 6c 6f 63 6b 20 66 69 6c 65 20 22 25 73 22 2e 00 6c 6f 63 6b 20 66 69 6c 65 20 66 61 69 6c 65 64 20 22 25 73 22 2e 00 6c 6f 63 6b 20 66 69 6c 65 20 73 75 63 63 65 73 73 20 22 25 73 22 2e 00 28 29 56 00 2d 6f 00 6f 6e 50 72 6f 63 65 73 73 } //01 00 
		$a_00_1 = {6c 6f 63 6b 20 66 69 6c 65 20 73 75 63 63 65 73 73 } //01 00  lock file success
		$a_00_2 = {66 6f 72 6b 20 63 68 69 6c 64 20 70 72 6f 63 65 73 73 } //00 00  fork child process
	condition:
		any of ($a_*)
 
}