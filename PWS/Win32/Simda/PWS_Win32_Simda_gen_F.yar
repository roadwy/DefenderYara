
rule PWS_Win32_Simda_gen_F{
	meta:
		description = "PWS:Win32/Simda.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 6c 6f 62 c7 45 90 01 01 61 6c 5c 4d c7 45 90 01 01 69 63 72 6f c7 45 90 01 01 73 6f 66 74 c7 45 90 01 01 53 79 73 65 c7 45 90 01 01 6e 74 65 72 c7 45 90 01 01 47 61 74 65 66 c7 90 01 01 f4 90 01 01 00 ff 15 90 00 } //01 00 
		$a_01_1 = {64 61 62 65 74 72 65 73 77 65 35 70 75 70 68 45 67 61 77 72 65 64 65 33 72 65 73 77 75 73 61 } //01 00  dabetreswe5puphEgawrede3reswusa
		$a_01_2 = {26 63 6f 6d 6d 61 6e 64 3d 62 63 5f 61 63 74 69 76 61 74 65 26 73 74 61 74 75 73 3d } //00 00  &command=bc_activate&status=
	condition:
		any of ($a_*)
 
}