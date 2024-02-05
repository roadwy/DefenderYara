
rule TrojanSpy_Win32_Rebhip_C{
	meta:
		description = "TrojanSpy:Win32/Rebhip.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 06 00 "
		
	strings :
		$a_01_0 = {23 23 23 23 40 23 23 23 23 20 23 23 23 23 40 23 23 23 23 } //01 00 
		$a_01_1 = {43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 } //01 00 
		$a_01_2 = {58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 } //01 00 
		$a_01_3 = {06 00 53 00 50 00 59 00 4e 00 45 00 54 00 } //01 00 
		$a_01_4 = {7c 53 70 79 2d 4e 65 74 20 5b 52 41 54 5d 7c } //00 00 
		$a_00_5 = {80 10 00 00 9a c9 } //9a 07 
	condition:
		any of ($a_*)
 
}