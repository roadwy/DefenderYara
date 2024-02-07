
rule PWS_Win32_Lolyda_BB{
	meta:
		description = "PWS:Win32/Lolyda.BB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 02 00 17 00 90 01 01 c7 45 fc 0e 01 01 00 89 90 01 01 08 89 90 01 01 f8 ff 15 90 01 04 85 c0 74 09 f6 45 08 20 74 03 6a 01 90 00 } //01 00 
		$a_01_1 = {b9 89 02 00 00 33 c0 8d bd } //01 00 
		$a_01_2 = {25 73 7e 7e 25 30 36 78 2e 7e 7e 7e } //00 00  %s~~%06x.~~~
	condition:
		any of ($a_*)
 
}