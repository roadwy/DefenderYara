
rule Backdoor_Linux_Caem_A_xp{
	meta:
		description = "Backdoor:Linux/Caem.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6c 66 2e 65 58 70 2e 44 69 6d 75 6c 61 69 } //01 00  alf.eXp.Dimulai
		$a_01_1 = {44 61 74 61 6e 67 20 44 69 20 65 58 70 6c 6f 69 74 20 53 68 65 6c 6c } //01 00  Datang Di eXploit Shell
		$a_01_2 = {64 65 6e 67 61 6e 20 70 69 64 } //01 00  dengan pid
		$a_01_3 = {61 6c 66 2e 65 58 70 6c 6f 69 74 2e 73 68 65 6c 6c } //00 00  alf.eXploit.shell
	condition:
		any of ($a_*)
 
}