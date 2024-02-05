
rule TrojanDropper_Win32_Jevafus_A{
	meta:
		description = "TrojanDropper:Win32/Jevafus.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff ff e9 a2 01 00 00 49 0f f6 3c cf 75 ee c0 0f 31 8b c8 0f 31 2b c8 f7 d1 81 f9 00 50 00 00 7f fe 0f 31 8b c8 0f 31 2b c8 f7 d1 81 f9 00 50 00 00 } //01 00 
		$a_01_1 = {7f fe d6 0f 88 dd 01 00 00 0f 89 d7 01 00 00 3e c1 c3 05 c1 cb 05 36 0f 8a 01 02 00 00 0f 8b fb 01 00 00 5b e8 0b 00 00 00 72 65 67 69 73 74 65 72 65 64 } //f6 ff 
		$a_00_2 = {28 00 43 00 29 00 20 00 47 00 72 00 61 00 6e 00 64 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 2e 00 20 00 4c 00 74 00 64 00 2e 00 } //00 00 
	condition:
		any of ($a_*)
 
}