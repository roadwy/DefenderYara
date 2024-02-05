
rule Backdoor_Win32_Farfli_AQ{
	meta:
		description = "Backdoor:Win32/Farfli.AQ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe6 00 ffffffdc 00 09 00 00 64 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 63 c6 45 f1 61 c6 45 f2 6f c6 45 f3 6e c6 45 f4 66 c6 45 f5 7a c6 45 f6 32 } //32 00 
		$a_01_1 = {c6 85 34 fe ff ff 4c c6 85 35 fe ff ff 4f c6 85 36 fe ff ff 56 c6 85 37 fe ff ff 45 c6 85 38 fe ff ff 54 } //32 00 
		$a_01_2 = {c6 45 f7 5c c6 45 f8 5c c6 45 f9 42 c6 45 fa 45 c6 45 fb 45 c6 45 fc 50 } //32 00 
		$a_01_3 = {c6 85 6d ff ff ff 73 c6 85 6e ff ff ff 74 c6 85 6f ff ff ff 73 c6 85 70 ff ff ff 63 c6 85 71 ff ff ff 2e } //14 00 
		$a_01_4 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72 } //14 00 
		$a_01_5 = {75 02 eb 3f 8b 55 fc c6 02 76 8b 45 f4 50 8b 4d f0 51 8b 55 fc 83 c2 01 } //0a 00 
		$a_01_6 = {77 6f 77 2e 65 78 65 00 74 77 32 2e 65 78 65 } //05 00 
		$a_01_7 = {3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e } //05 00 
		$a_01_8 = {74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 38 38 38 38 2f 69 70 2e 74 78 74 } //00 00 
		$a_00_9 = {5d 04 00 00 29 fc 02 80 5c 23 00 00 2a fc 02 80 00 00 01 00 22 00 0d 00 cf 01 49 6e 6a 65 63 74 6f 72 2e 45 52 00 00 01 40 05 82 31 00 04 00 80 10 00 00 51 ff 59 3c 24 d6 69 ba 52 83 e8 91 de 00 } //00 80 
	condition:
		any of ($a_*)
 
}