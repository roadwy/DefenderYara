
rule Worm_Win32_Mira_J_ibt{
	meta:
		description = "Worm:Win32/Mira.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 61 61 61 6c 61 6d 6d } //01 00  Saaaalamm
		$a_01_1 = {5c 4d 69 72 61 2e 68 } //01 00  \Mira.h
		$a_00_2 = {01 d0 8d 14 85 00 00 00 00 01 d0 29 c1 89 c8 04 61 88 03 8d 45 f8 ff 00 eb b8 } //01 00 
		$a_02_3 = {c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 10 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}