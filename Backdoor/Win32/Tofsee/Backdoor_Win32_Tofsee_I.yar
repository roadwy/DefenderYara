
rule Backdoor_Win32_Tofsee_I{
	meta:
		description = "Backdoor:Win32/Tofsee.I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {8a 14 06 32 55 14 88 10 8a d1 02 55 18 f6 d9 00 55 14 40 4f 75 ea } //04 00 
		$a_01_1 = {76 0f 8b 44 24 04 03 c1 f6 10 41 3b 4c 24 08 72 f1 c3 } //01 00 
		$a_03_2 = {59 59 7f 12 46 8b c6 c1 e0 03 8d 88 90 01 04 39 19 75 c1 eb 0e 90 00 } //01 00 
		$a_01_3 = {73 65 63 75 70 64 61 74 2e 64 61 74 } //01 00  secupdat.dat
		$a_01_4 = {5c 00 5c 00 2e 00 5c 00 72 00 6f 00 74 00 63 00 65 00 74 00 6f 00 72 00 70 00 } //01 00  \\.\rotcetorp
		$a_03_5 = {83 f8 0e 7d 1e 0f b6 80 90 01 04 83 e8 00 74 36 48 74 29 48 74 1c 48 74 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}