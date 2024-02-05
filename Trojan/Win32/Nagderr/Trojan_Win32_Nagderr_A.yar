
rule Trojan_Win32_Nagderr_A{
	meta:
		description = "Trojan:Win32/Nagderr.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 02 74 0a 83 f8 03 74 05 83 f8 04 75 05 e8 90 01 04 80 3d 90 01 04 5a 72 cc 90 00 } //01 00 
		$a_01_1 = {3d 2e 68 74 6d 74 12 3d 2e 70 68 70 74 0b 3d 2e 61 73 70 0f 85 } //01 00 
		$a_01_2 = {80 3f 2f 75 f2 80 7f 05 3e 75 ec 8b 57 01 81 e2 df df df df 81 fa 42 4f 44 59 75 db } //00 00 
	condition:
		any of ($a_*)
 
}