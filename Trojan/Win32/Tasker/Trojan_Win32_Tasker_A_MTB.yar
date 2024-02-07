
rule Trojan_Win32_Tasker_A_MTB{
	meta:
		description = "Trojan:Win32/Tasker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 49 02 49 81 e9 06 00 00 00 49 63 d2 44 0f ab fa 66 44 0f ac f2 9f 66 41 d3 e0 0f b7 d7 49 0f bf d0 66 45 89 41 08 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tasker_A_MTB_2{
	meta:
		description = "Trojan:Win32/Tasker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 81 ed 10 00 00 00 81 ed 90 01 04 e9 90 02 10 b8 90 01 04 03 c5 81 c0 4c 00 00 00 b9 bc 05 00 00 ba 60 78 0a da 30 10 40 49 90 00 } //01 00 
		$a_01_1 = {74 67 31 36 37 41 41 37 35 30 } //00 00  tg167AA750
	condition:
		any of ($a_*)
 
}