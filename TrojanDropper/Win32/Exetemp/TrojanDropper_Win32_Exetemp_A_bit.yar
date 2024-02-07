
rule TrojanDropper_Win32_Exetemp_A_bit{
	meta:
		description = "TrojanDropper:Win32/Exetemp.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 04 01 de 41 3b ca 72 f7 } //01 00 
		$a_03_1 = {6a 01 8d 3c 2e 53 53 57 68 90 01 04 53 ff 15 90 01 04 57 ff 15 90 01 04 8d 74 06 01 3b 74 24 20 72 90 00 } //01 00 
		$a_03_2 = {83 c4 10 68 90 01 04 ff 15 90 01 04 6a 0a ff 15 90 01 04 8b 54 24 90 01 01 8b 44 24 90 01 01 83 c2 10 83 c7 20 48 89 54 24 90 01 01 89 44 24 90 01 01 75 90 00 } //01 00 
		$a_01_3 = {45 58 45 5f 74 65 6d 70 25 78 25 73 } //00 00  EXE_temp%x%s
	condition:
		any of ($a_*)
 
}