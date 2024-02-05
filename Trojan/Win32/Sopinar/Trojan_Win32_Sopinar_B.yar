
rule Trojan_Win32_Sopinar_B{
	meta:
		description = "Trojan:Win32/Sopinar.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 3c 31 22 11 22 11 75 90 01 01 c7 04 31 90 00 } //01 00 
		$a_01_1 = {7b 38 36 31 65 34 64 38 61 2d 31 36 38 62 2d 34 62 39 30 2d 61 30 34 66 2d 33 34 66 37 32 65 65 37 30 31 65 30 7d } //00 00 
	condition:
		any of ($a_*)
 
}