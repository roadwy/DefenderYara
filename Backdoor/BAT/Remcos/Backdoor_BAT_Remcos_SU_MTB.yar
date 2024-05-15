
rule Backdoor_BAT_Remcos_SU_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_81_0 = {4e 6f 74 54 68 65 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //02 00  NotThere.Properties.Resources.resources
		$a_81_1 = {24 33 37 63 65 63 34 38 35 2d 30 30 61 36 2d 34 66 34 37 2d 39 30 33 35 2d 31 35 63 61 34 38 36 39 35 39 64 38 } //02 00  $37cec485-00a6-4f47-9035-15ca486959d8
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 53 61 61 64 38 38 38 2f 41 75 74 6f 53 79 6e 74 68 65 73 69 73 2f 69 73 73 75 65 73 } //00 00  https://github.com/Saad888/AutoSynthesis/issues
	condition:
		any of ($a_*)
 
}