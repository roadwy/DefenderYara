
rule TrojanDropper_Win32_Barlaiy_A_dha{
	meta:
		description = "TrojanDropper:Win32/Barlaiy.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {99 b9 00 00 90 01 f7 f9 bf 00 00 20 03 2b fa } //01 00 
		$a_03_1 = {68 00 6a 02 00 68 90 01 04 56 e8 90 01 04 8b 44 24 90 01 01 81 c6 00 6a 02 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}