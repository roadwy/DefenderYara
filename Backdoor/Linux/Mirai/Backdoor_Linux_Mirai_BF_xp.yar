
rule Backdoor_Linux_Mirai_BF_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BF!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 65 73 74 49 50 3d 77 67 65 74 90 02 20 2f 62 69 6e 73 2e 73 68 90 00 } //01 00 
		$a_01_1 = {25 32 30 73 68 25 32 30 62 69 6e 73 2e 73 68 } //01 00  %20sh%20bins.sh
		$a_01_2 = {63 6d 64 4d 65 74 68 6f 64 3d 70 69 6e 67 } //01 00  cmdMethod=ping
		$a_01_3 = {36 53 52 53 3e 42 } //00 00  6SRS>B
	condition:
		any of ($a_*)
 
}