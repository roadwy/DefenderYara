
rule Backdoor_Win32_Farfli_AH{
	meta:
		description = "Backdoor:Win32/Farfli.AH,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe6 00 ffffffc8 00 08 00 00 64 00 "
		
	strings :
		$a_01_0 = {b2 e9 d5 d2 46 57 4b 4a 47 48 ca a7 b0 dc a3 ac cd cb b3 f6 00 } //64 00 
		$a_01_1 = {c6 45 ec 46 c6 45 ed 57 c6 45 ee 4b c6 45 ef 4a 8b 55 ec 8d 8e b0 } //14 00 
		$a_01_2 = {c6 45 dc 77 c6 45 dd 61 c6 45 de 76 88 5d df } //14 00 
		$a_01_3 = {c6 45 f4 72 c6 45 f5 65 c6 45 f6 63 c6 45 f7 76 c6 45 f8 00 } //14 00 
		$a_01_4 = {b0 65 b2 74 88 45 e9 88 45 eb 88 45 ed 88 45 f7 8d 45 e8 b1 69 } //0a 00 
		$a_01_5 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72 } //0a 00 
		$a_01_6 = {0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //0a 00 
		$a_01_7 = {c6 45 f0 47 c6 45 f1 48 66 8b 45 f0 89 11 c7 86 a8 00 00 00 ff ff ff ff 66 89 41 04 } //00 00 
		$a_00_8 = {5d 04 00 00 b9 fa 02 80 5c 22 00 00 ba fa 02 80 00 00 01 00 27 00 0c 00 c8 21 42 61 6e 63 6f 73 2e 41 4a 45 00 00 01 40 05 82 5f 00 04 00 87 10 00 00 } //35 18 
	condition:
		any of ($a_*)
 
}