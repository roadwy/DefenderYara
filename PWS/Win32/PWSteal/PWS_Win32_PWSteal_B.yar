
rule PWS_Win32_PWSteal_B{
	meta:
		description = "PWS:Win32/PWSteal.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 ec 04 66 3d 01 80 0f 85 b9 04 00 00 } //01 00 
		$a_00_1 = {4c 49 42 47 43 43 57 33 32 2d 45 48 2d 32 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 } //01 00  LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32
		$a_03_2 = {40 7e 35 66 83 90 01 02 5a 7f 2e 0f b7 90 01 02 83 c0 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}