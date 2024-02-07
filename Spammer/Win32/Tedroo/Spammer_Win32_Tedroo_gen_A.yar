
rule Spammer_Win32_Tedroo_gen_A{
	meta:
		description = "Spammer:Win32/Tedroo.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0b 00 00 03 00 "
		
	strings :
		$a_03_0 = {04 20 32 45 ff 47 88 04 33 b8 90 01 04 8d 48 01 8a 10 90 00 } //03 00 
		$a_01_1 = {57 bf 0d 00 00 00 01 7c 24 04 5f ff e7 } //02 00 
		$a_01_2 = {33 db 81 c3 7e 66 04 80 } //02 00 
		$a_01_3 = {8a d0 80 c2 54 30 14 01 40 3b c6 72 f3 } //02 00 
		$a_01_4 = {0f 01 0c 24 b8 00 00 00 00 0b 44 24 02 83 c4 08 3d 00 00 00 d0 } //02 00 
		$a_01_5 = {2f 73 70 6d 2f 73 5f } //02 00  /spm/s_
		$a_01_6 = {53 50 4d 5f 4e 45 54 } //01 00  SPM_NET
		$a_01_7 = {25 73 3f 76 65 72 3d 25 64 } //01 00  %s?ver=%d
		$a_01_8 = {24 54 4f 5f 45 4d 41 49 4c } //01 00  $TO_EMAIL
		$a_01_9 = {5f 69 64 2e 64 61 74 } //01 00  _id.dat
		$a_01_10 = {64 6f 5f 77 6f 72 6b } //00 00  do_work
	condition:
		any of ($a_*)
 
}