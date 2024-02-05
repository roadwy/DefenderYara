
rule Backdoor_Win64_Drixed_C{
	meta:
		description = "Backdoor:Win64/Drixed.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 fa 03 75 07 e8 90 01 04 eb 90 01 01 85 d2 75 90 01 01 3d ee ac ff e7 75 90 00 } //01 00 
		$a_01_1 = {81 bb 00 04 00 00 ef be ad de } //01 00 
		$a_01_2 = {63 6c 69 63 6b 73 68 6f 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}