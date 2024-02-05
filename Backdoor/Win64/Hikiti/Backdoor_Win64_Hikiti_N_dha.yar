
rule Backdoor_Win64_Hikiti_N_dha{
	meta:
		description = "Backdoor:Win64/Hikiti.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 32 c2 88 01 48 8d 41 01 33 c9 0f 1f 80 00 00 00 00 30 14 01 74 0c 48 ff c1 48 81 f9 03 01 00 00 7c ef } //01 00 
		$a_01_1 = {c6 44 24 26 ed c6 44 24 27 ed c6 44 24 28 ee c6 44 24 29 e2 c6 } //00 00 
	condition:
		any of ($a_*)
 
}