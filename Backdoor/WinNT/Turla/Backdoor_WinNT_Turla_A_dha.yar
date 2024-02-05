
rule Backdoor_WinNT_Turla_A_dha{
	meta:
		description = "Backdoor:WinNT/Turla.A!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 01 4c 24 10 8b 44 24 12 0f b7 48 06 0f b7 00 c1 e1 10 0b c8 51 e8 } //01 00 
		$a_01_1 = {76 1b 8a 04 0e 88 04 0f 6a 0f } //00 00 
	condition:
		any of ($a_*)
 
}