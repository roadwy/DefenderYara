
rule PWS_Win32_Lolyda_AC{
	meta:
		description = "PWS:Win32/Lolyda.AC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 f2 9a 88 10 40 4e 75 f4 } //01 00 
		$a_01_1 = {8a 14 08 80 f2 9a 88 11 41 4e 75 f4 } //01 00 
		$a_00_2 = {8b 48 fc 8b 30 2b ce 83 e9 05 89 48 f8 } //01 00 
		$a_00_3 = {8b 48 fc 2b 08 83 e9 05 89 48 f8 } //01 00 
		$a_01_4 = {74 04 2c 05 eb 02 2c 0a 88 84 0d } //01 00 
		$a_02_5 = {66 6f 6e 74 73 5c 67 90 03 02 02 74 68 62 6d 90 00 } //05 00 
		$a_00_6 = {26 7a 6f 6e 65 3d 25 73 26 73 65 72 76 65 72 3d 25 73 26 6e 61 6d 65 3d 25 73 26 70 61 73 73 } //00 00  &zone=%s&server=%s&name=%s&pass
	condition:
		any of ($a_*)
 
}