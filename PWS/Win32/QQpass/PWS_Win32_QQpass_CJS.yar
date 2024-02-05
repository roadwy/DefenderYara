
rule PWS_Win32_QQpass_CJS{
	meta:
		description = "PWS:Win32/QQpass.CJS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1 } //01 00 
		$a_00_1 = {2e 41 70 70 41 63 74 69 76 61 74 65 20 22 51 51 b5 c7 c2 bc 22 } //01 00 
		$a_00_2 = {3f 51 51 4e 75 6d 62 65 72 3d } //01 00 
		$a_00_3 = {26 51 51 50 61 73 73 57 6f 72 64 3d } //01 00 
		$a_00_4 = {54 58 47 75 69 46 6f 75 6e 64 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}