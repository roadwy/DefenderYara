
rule Backdoor_BAT_AgentTesla_SBR_MSR{
	meta:
		description = "Backdoor:BAT/AgentTesla.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 75 70 69 67 64 68 69 79 70 6f 61 67 64 70 69 79 64 67 70 69 64 79 67 64 69 } //01 00  hupigdhiypoagdpiydgpidygdi
		$a_01_1 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  Encrypted
		$a_01_2 = {6e 00 65 00 77 00 77 00 6f 00 72 00 6c 00 64 00 6f 00 72 00 64 00 65 00 } //00 00  newworldorde
	condition:
		any of ($a_*)
 
}