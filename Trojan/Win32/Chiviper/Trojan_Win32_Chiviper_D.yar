
rule Trojan_Win32_Chiviper_D{
	meta:
		description = "Trojan:Win32/Chiviper.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 64 ff d7 a1 90 01 04 83 f8 03 74 05 83 f8 01 75 ed 90 00 } //01 00 
		$a_01_1 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 6f 73 3d 25 73 } //01 00 
		$a_00_2 = {77 65 62 73 72 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}