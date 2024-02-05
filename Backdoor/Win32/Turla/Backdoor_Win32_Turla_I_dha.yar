
rule Backdoor_Win32_Turla_I_dha{
	meta:
		description = "Backdoor:Win32/Turla.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 74 04 10 55 40 83 f8 0c 72 f5 } //01 00 
		$a_01_1 = {69 73 70 3d 25 64 20 63 70 3d 25 53 20 64 62 70 3d 25 53 20 68 6d 6f 64 3d 30 78 25 30 38 58 } //00 00 
	condition:
		any of ($a_*)
 
}