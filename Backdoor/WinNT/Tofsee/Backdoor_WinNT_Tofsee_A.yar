
rule Backdoor_WinNT_Tofsee_A{
	meta:
		description = "Backdoor:WinNT/Tofsee.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {2b fe 8a c1 90 01 02 b3 90 01 01 f6 eb 8d 14 31 32 04 17 41 81 f9 90 01 02 00 00 88 02 75 e7 90 00 } //02 00 
		$a_03_1 = {47 47 66 3b c3 75 f5 8d 90 01 02 f7 ff ff be 90 01 04 50 f3 a5 90 00 } //02 00 
		$a_03_2 = {68 c0 a6 00 00 8d 90 01 03 ff ff 50 8d 45 90 01 01 50 53 90 00 } //01 00 
		$a_00_3 = {2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  /index.html
		$a_01_4 = {48 6f 74 20 69 6e 74 65 72 6e 65 74 20 6f 66 66 65 72 73 00 } //00 00  潈⁴湩整湲瑥漠晦牥s
	condition:
		any of ($a_*)
 
}