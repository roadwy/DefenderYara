
rule PWS_Win32_Ygebanel_A{
	meta:
		description = "PWS:Win32/Ygebanel.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 } //01 00 
		$a_00_1 = {45 6e 74 72 65 20 6e 6f 20 59 61 68 6f 6f } //01 00 
		$a_00_2 = {2d 63 6f 6e 74 61 74 6f 73 2e 74 78 74 } //01 00 
		$a_00_3 = {68 6f 74 73 65 6e 64 64 } //00 00 
	condition:
		any of ($a_*)
 
}