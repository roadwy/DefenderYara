
rule Backdoor_Win64_Drixed_C{
	meta:
		description = "Backdoor:Win64/Drixed.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fa 03 75 07 e8 ?? ?? ?? ?? eb ?? 85 d2 75 ?? 3d ee ac ff e7 75 } //5
		$a_01_1 = {81 bb 00 04 00 00 ef be ad de } //1
		$a_01_2 = {63 6c 69 63 6b 73 68 6f 74 00 } //1 汣捩獫潨t
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}