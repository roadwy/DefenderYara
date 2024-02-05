
rule TrojanProxy_Win32_Bunitu_B{
	meta:
		description = "TrojanProxy:Win32/Bunitu.B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {81 2c 24 57 75 17 00 8f 00 c7 40 04 69 6c 33 32 } //05 00 
		$a_01_1 = {c7 00 3a 2a 3a 45 5a } //05 00 
		$a_03_2 = {c1 ca 08 03 d0 8b df b8 2e 00 00 00 90 03 07 06 b9 10 00 00 00 f2 ae 33 c9 41 c1 e1 03 90 00 } //01 00 
		$a_01_3 = {65 6e 67 69 6e 65 20 32 2e 35 31 3c 2f 66 6f 6e 74 3e } //01 00 
		$a_01_4 = {77 72 72 72 2f 31 2e 30 20 32 30 30 20 4f 4b } //05 00 
		$a_01_5 = {c7 40 04 69 6c 33 32 ff 48 04 ff 48 04 83 68 04 01 ff 48 04 } //00 00 
	condition:
		any of ($a_*)
 
}