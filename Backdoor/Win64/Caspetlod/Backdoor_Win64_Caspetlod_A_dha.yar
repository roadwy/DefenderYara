
rule Backdoor_Win64_Caspetlod_A_dha{
	meta:
		description = "Backdoor:Win64/Caspetlod.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 00 c7 44 24 38 48 31 c0 c3 ff 15 } //01 00 
		$a_00_1 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 00 00 00 73 79 73 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}