
rule Backdoor_Win32_Taroca_A{
	meta:
		description = "Backdoor:Win32/Taroca.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {34 6f 80 f1 70 88 44 24 5e a1 90 01 04 88 4c 24 5c 8a c8 8a c4 34 75 80 f2 72 88 44 24 60 66 a1 90 01 04 88 54 24 5d 8a d0 8a c4 80 f1 64 34 74 88 4c 24 5f 88 44 24 62 bf 90 01 04 83 c9 ff 33 c0 80 f2 63 90 00 } //01 00 
		$a_01_1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6d 73 2d 78 62 61 70 } //01 00  application/x-ms-xbap
		$a_01_2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 78 70 73 64 6f 63 75 6d 65 6e 74 } //01 00  application/vnd.ms-xpsdocument
		$a_01_3 = {53 65 74 20 72 65 74 75 72 6e 20 74 69 6d 65 20 65 72 72 6f 72 20 3d 20 25 64 21 } //03 00  Set return time error = %d!
		$a_03_4 = {80 f1 49 88 4e 0e 8a 15 90 01 04 80 f2 42 88 56 0f 8a 0d 90 01 04 80 f1 4d 88 4e 10 8a 15 90 01 04 80 f2 4c 88 56 11 8a 0d 90 01 04 80 f1 6f 88 4e 12 8a 15 90 01 04 80 f2 74 88 56 13 8a 0d 90 01 04 80 f1 75 88 4e 14 8a 15 90 01 04 80 f2 73 88 56 15 8a 0d 90 01 04 80 f1 4d 88 4e 16 8a 15 90 01 04 80 f2 53 88 56 17 5e 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 7a } //24 03 
	condition:
		any of ($a_*)
 
}