
rule PWS_Win32_Savnut_B{
	meta:
		description = "PWS:Win32/Savnut.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 6e 65 74 62 61 6e 6b 65 5f 25 73 5f 25 73 } //01 00  %snetbanke_%s_%s
		$a_01_1 = {2a 78 69 74 69 5b 2a } //01 00  *xiti[*
		$a_01_2 = {26 63 68 65 63 6b 3d 63 68 63 6b } //02 00  &check=chck
		$a_01_3 = {81 3f 6e 6f 6e 65 74 } //02 00 
		$a_01_4 = {c7 07 55 53 46 3d af 33 c0 } //02 00 
		$a_01_5 = {b8 47 00 00 00 ba 6f 6f 67 6c b9 fc 0f 00 00 f2 ae } //02 00 
		$a_01_6 = {ac aa 3c 40 75 fa 8b d7 8b 7d e8 8b cf b8 0a 00 00 00 f2 ae } //02 00 
		$a_01_7 = {85 c0 74 08 8b 45 fc 80 38 40 75 0e ff 75 f0 } //00 00 
	condition:
		any of ($a_*)
 
}