
rule Virus_Linux_Ovets_A_xp{
	meta:
		description = "Virus:Linux/Ovets.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 61 63 6b 6e 69 78 2e 61 73 6d } //1 hacknix.asm
		$a_01_1 = {74 72 79 20 74 6f 20 69 6e 66 65 63 74 } //1 try to infect
		$a_01_2 = {5b 68 41 63 6b 6e 69 58 20 3c 40 29 29 3e 3c 20 50 69 65 6e 53 74 65 56 6f 5d 4c } //1 [hAckniX <@))>< PienSteVo]L
		$a_01_3 = {66 69 72 73 74 20 62 61 6c 72 6f 67 65 64 20 70 67 6d } //1 first balroged pgm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}