
rule Backdoor_Win32_Farfli_AD{
	meta:
		description = "Backdoor:Win32/Farfli.AD,SIGNATURE_TYPE_PEHSTR_EXT,36 01 0e 01 07 00 00 64 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 5c c6 45 e9 6f c6 45 ea 75 c6 45 eb 72 c6 45 ec 6c } //64 00 
		$a_01_1 = {89 45 d4 66 c7 45 d8 00 00 b9 09 00 00 00 33 c0 8d 7d da f3 ab 66 ab c7 45 a4 } //32 00 
		$a_01_2 = {c6 45 f9 5c c6 45 fa 42 c6 45 fb 49 c6 45 fc 54 c6 45 fd 53 } //32 00 
		$a_01_3 = {c6 45 b0 25 c6 45 b1 73 c6 45 b2 5c c6 45 b3 2a c6 45 b4 2e c6 45 b5 2a c6 45 b6 00 } //14 00 
		$a_01_4 = {c6 85 30 fe ff ff 5c c6 85 31 fe ff ff 63 c6 85 32 fe ff ff 6d c6 85 33 fe ff ff 64 } //14 00 
		$a_01_5 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72 } //0a 00 
		$a_01_6 = {3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e } //00 00  <H1>403 Forbidden</H1>
		$a_00_7 = {5d 04 00 00 3c fa 02 80 5c 21 00 00 3d fa 02 80 00 00 01 00 06 00 0b 00 84 21 46 61 72 66 } //6c 69 
	condition:
		any of ($a_*)
 
}