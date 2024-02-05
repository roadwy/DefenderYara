
rule Trojan_Win32_Tracur_AE{
	meta:
		description = "Trojan:Win32/Tracur.AE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d ce 07 00 00 77 0a be d0 07 00 00 } //01 00 
		$a_01_1 = {8a 44 2f 01 83 c5 01 2c 67 83 c1 01 3c 0f } //00 00 
	condition:
		any of ($a_*)
 
}