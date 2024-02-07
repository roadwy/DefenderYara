
rule PWS_Win32_Kheagol_G{
	meta:
		description = "PWS:Win32/Kheagol.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 2e 70 68 70 } //01 00  data.php
		$a_01_1 = {61 3d 25 73 26 62 3d 25 73 26 63 3d 25 73 } //01 00  a=%s&b=%s&c=%s
		$a_01_2 = {68 e3 ca 1d 56 } //01 00 
		$a_01_3 = {68 bd d9 e9 5d } //00 00 
	condition:
		any of ($a_*)
 
}