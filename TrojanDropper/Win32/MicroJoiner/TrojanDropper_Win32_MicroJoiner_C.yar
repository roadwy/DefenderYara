
rule TrojanDropper_Win32_MicroJoiner_C{
	meta:
		description = "TrojanDropper:Win32/MicroJoiner.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {83 c4 08 83 c3 90 01 01 83 ef 01 75 ee 56 ff 15 90 00 } //03 00 
		$a_02_1 = {8d 44 3e fc 8b 38 8b cf 6b c9 90 01 01 53 2b c1 8b d8 51 53 e8 90 00 } //01 00 
		$a_00_2 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 80 8d 54 24 20 52 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}