
rule Worm_Win32_Soulclose_B{
	meta:
		description = "Worm:Win32/Soulclose.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 00 70 00 65 00 6e 00 59 00 6f 00 75 00 72 00 53 00 6f 00 75 00 6c 00 } //01 00  OpenYourSoul
		$a_00_1 = {6b 00 69 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 } //01 00  kill.bat
		$a_02_2 = {63 00 66 00 2e 00 65 00 78 00 65 00 90 02 12 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 90 02 12 5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 90 02 12 6f 00 70 00 65 00 6e 00 3d 00 63 00 66 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}