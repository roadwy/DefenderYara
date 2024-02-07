
rule _PseudoThreat_40000025{
	meta:
		description = "!PseudoThreat_40000025,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 } //01 00 
		$a_01_1 = {49 45 53 50 6c 75 67 69 6e } //02 00  IESPlugin
		$a_02_2 = {56 68 04 01 00 00 6a 00 be 90 01 04 56 e8 90 01 04 ff 74 24 14 e8 90 01 04 83 c4 10 48 78 1a 8b 4c 24 08 2b ce 8a 94 01 90 01 04 32 54 24 0c 48 88 90 90 90 01 04 79 ec 8b c6 5e c3 90 00 } //02 00 
		$a_02_3 = {8a 08 40 84 c9 75 f9 2b c2 48 78 1c 8a 4c 24 90 01 01 81 90 01 05 8a 94 90 01 05 32 d1 48 88 90 90 90 01 04 79 ee 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}