
rule Backdoor_Win32_Turla_H_dha{
	meta:
		description = "Backdoor:Win32/Turla.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 4c 05 98 40 83 f8 0c 72 f6 } //01 00 
		$a_01_1 = {c7 45 b8 2e 64 6f 63 88 5d bc c7 45 d8 2e 70 64 66 } //00 00 
	condition:
		any of ($a_*)
 
}