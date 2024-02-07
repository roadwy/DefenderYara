
rule Backdoor_Linux_Potic_A_xp{
	meta:
		description = "Backdoor:Linux/Potic.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 73 6f 74 6e 69 63 2d 30 2e 32 2e 35 } //01 00  psotnic-0.2.5
		$a_01_1 = {42 6f 74 73 20 6f 6e 2d 6c 69 6e 65 } //01 00  Bots on-line
		$a_01_2 = {70 73 6f 74 6e 69 63 2a 2e 74 61 72 2e 67 7a } //01 00  psotnic*.tar.gz
		$a_01_3 = {2e 62 6f 74 73 20 5b 65 78 70 72 5d 20 5b 66 6c 61 67 73 5d 20 2e 73 74 61 74 75 73 20 5b 62 6f 74 5d } //00 00  .bots [expr] [flags] .status [bot]
	condition:
		any of ($a_*)
 
}