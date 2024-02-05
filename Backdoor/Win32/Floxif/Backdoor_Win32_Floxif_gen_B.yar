
rule Backdoor_Win32_Floxif_gen_B{
	meta:
		description = "Backdoor:Win32/Floxif.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_80_0 = {5c 73 70 6f 6f 6c 5c 70 72 74 70 72 6f 63 73 5c 77 33 32 78 38 36 5c 6c 6f 63 61 6c 73 70 6c 2e 64 6c 6c } //\spool\prtprocs\w32x86\localspl.dll  02 00 
		$a_03_1 = {68 19 00 02 00 8d 45 90 01 01 6a 00 50 68 02 00 00 80 c7 45 90 01 01 30 30 31 00 90 00 } //01 00 
		$a_01_2 = {8a d0 8a c1 b3 07 f6 eb 2c 33 32 c2 88 44 0d } //01 00 
		$a_03_3 = {b8 17 93 28 f3 33 c8 89 7d 90 01 01 89 0f 90 00 } //02 00 
		$a_01_4 = {c7 00 03 00 00 00 50 8d 46 60 6a 00 50 ff 76 20 ff 52 14 fe 46 62 } //00 00 
		$a_00_5 = {5d 04 00 00 } //08 a9 
	condition:
		any of ($a_*)
 
}