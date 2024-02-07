
rule Backdoor_Win64_Turla_B_dha{
	meta:
		description = "Backdoor:Win64/Turla.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 80 33 55 49 ff c3 48 83 e8 01 75 f3 } //01 00 
		$a_01_1 = {43 0f b6 04 01 49 ff c1 41 30 04 0a 49 83 f9 01 4c 0f 4d cb 49 ff c2 4d 3b d3 7c e4 } //01 00 
		$a_01_2 = {25 49 36 34 75 43 25 75 4b 25 75 4e 30 2e 6a 70 67 } //00 00  %I64uC%uK%uN0.jpg
	condition:
		any of ($a_*)
 
}