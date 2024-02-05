
rule DoS_Win32_WhisperGate_C_dha{
	meta:
		description = "DoS:Win32/WhisperGate.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 00 8c c8 8e d8 be 88 7c e8 00 00 50 fc 8a 90 01 01 3c 00 74 06 e8 05 00 46 eb f4 eb 05 b4 0e cd 10 90 00 } //01 00 
		$a_03_1 = {c3 8c c8 8e d8 a3 78 7c 66 c7 06 76 7c 82 7c 90 01 01 00 b4 43 b0 00 8a 16 87 7c 80 c2 80 be 72 7c cd 90 00 } //01 00 
		$a_03_2 = {13 72 02 73 18 fe 06 87 7c 66 c7 06 7a 7c 01 00 90 01 01 00 66 c7 06 7e 7c 00 00 00 00 eb c4 66 81 06 90 00 } //01 00 
		$a_03_3 = {7a 7c c7 00 00 00 66 81 16 7e 7c 00 00 00 90 01 01 f8 eb af 10 00 01 00 00 00 00 00 01 00 00 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}