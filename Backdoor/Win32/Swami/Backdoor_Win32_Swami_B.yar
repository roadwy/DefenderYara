
rule Backdoor_Win32_Swami_B{
	meta:
		description = "Backdoor:Win32/Swami.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c0 c8 03 49 88 81 90 01 04 75 e8 a0 90 01 04 34 35 90 09 0c 00 8a 81 90 01 04 32 81 90 00 } //01 00 
		$a_01_1 = {8b ec 8a 06 8a c8 02 c9 02 c9 02 c9 c0 e8 05 0a c8 32 4d 08 b8 01 00 00 00 88 0e 3b f8 76 1d 8a 0c 30 8a d1 02 d2 02 d2 02 d2 c0 e9 05 0a d1 32 54 30 ff 40 88 54 30 ff } //01 00 
		$a_01_2 = {79 61 68 6f 6f 20 74 61 6c 6b 20 75 70 64 61 74 65 } //00 00  yahoo talk update
	condition:
		any of ($a_*)
 
}