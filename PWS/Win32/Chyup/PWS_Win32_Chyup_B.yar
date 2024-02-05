
rule PWS_Win32_Chyup_B{
	meta:
		description = "PWS:Win32/Chyup.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 7c 02 ff 7c 75 17 8b 45 fc e8 } //01 00 
		$a_01_1 = {26 6f 70 74 3d 66 74 70 } //01 00 
		$a_01_2 = {26 6f 70 74 3d 67 72 61 62 } //00 00 
	condition:
		any of ($a_*)
 
}