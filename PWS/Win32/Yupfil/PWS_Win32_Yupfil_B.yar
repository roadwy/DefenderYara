
rule PWS_Win32_Yupfil_B{
	meta:
		description = "PWS:Win32/Yupfil.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a d0 80 c2 01 30 90 90 90 01 04 83 c0 01 83 f8 2e 72 ed 90 00 } //01 00 
		$a_00_1 = {3f 64 31 30 3d 25 73 26 64 37 31 3d 25 73 26 64 38 31 3d 25 73 26 64 38 32 } //01 00  ?d10=%s&d71=%s&d81=%s&d82
		$a_01_2 = {3f 64 30 31 3d 25 73 26 64 31 30 3d 25 73 } //02 00  ?d01=%s&d10=%s
		$a_03_3 = {c7 07 0c 00 00 00 e8 90 01 04 83 c3 01 83 c7 14 3b 1e 7c ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}