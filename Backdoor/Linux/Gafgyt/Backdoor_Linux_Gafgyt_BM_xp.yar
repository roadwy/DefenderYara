
rule Backdoor_Linux_Gafgyt_BM_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BM!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 70 6f 6f 6b 65 64 } //02 00  spooked
		$a_01_1 = {71 77 65 65 62 6f 74 6b 69 6c 6c 65 72 } //01 00  qweebotkiller
		$a_01_2 = {73 6e 69 66 66 73 6e 69 66 66 } //01 00  sniffsniff
		$a_01_3 = {73 70 6f 6f 6b 79 2d 6d 61 63 68 69 6e 65 } //00 00  spooky-machine
	condition:
		any of ($a_*)
 
}