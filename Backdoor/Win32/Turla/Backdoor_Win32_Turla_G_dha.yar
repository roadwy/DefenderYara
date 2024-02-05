
rule Backdoor_Win32_Turla_G_dha{
	meta:
		description = "Backdoor:Win32/Turla.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 4c 3d f0 40 83 f8 01 72 02 } //01 00 
		$a_01_1 = {30 01 46 3b 74 24 10 72 db } //01 00 
		$a_01_2 = {74 1c ff 36 ff 75 e8 53 53 68 2c 20 22 00 57 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}