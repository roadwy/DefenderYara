
rule Backdoor_Linux_Znaich_A_xp{
	meta:
		description = "Backdoor:Linux/Znaich.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 49 42 43 5f 46 41 54 41 4c 5f 53 54 44 45 52 52 5f } //01 00  LIBC_FATAL_STDERR_
		$a_00_1 = {25 64 2a 25 64 4d 48 5a } //01 00  %d*%dMHZ
		$a_00_2 = {47 45 54 43 4f 4e 46 5f 44 49 52 } //01 00  GETCONF_DIR
		$a_00_3 = {64 65 6c 65 74 65 5b 5d } //01 00  delete[]
		$a_00_4 = {4d 75 6c 74 69 68 6f 70 20 61 74 74 65 6d 70 74 65 64 } //00 00  Multihop attempted
	condition:
		any of ($a_*)
 
}