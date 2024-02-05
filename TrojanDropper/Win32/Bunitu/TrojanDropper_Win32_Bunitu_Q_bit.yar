
rule TrojanDropper_Win32_Bunitu_Q_bit{
	meta:
		description = "TrojanDropper:Win32/Bunitu.Q!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c2 01 c1 e2 03 c1 e2 03 8d 04 02 ba 90 01 04 52 8f 00 83 28 08 90 00 } //01 00 
		$a_03_1 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 90 01 04 87 d1 29 10 59 90 00 } //01 00 
		$a_03_2 = {50 33 f6 81 c6 62 89 03 00 2b 35 90 01 04 bf af 60 00 00 e8 90 01 04 66 03 c2 c1 e8 10 05 82 0e 00 00 83 c0 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}