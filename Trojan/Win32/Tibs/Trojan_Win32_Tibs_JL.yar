
rule Trojan_Win32_Tibs_JL{
	meta:
		description = "Trojan:Win32/Tibs.JL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f 6e e2 66 0f 7e e1 01 c1 31 d2 6a 90 01 01 db 1c 24 58 3d 00 00 00 80 75 c1 90 00 } //01 00 
		$a_01_1 = {68 ff ff 00 00 0f ae 14 24 58 6a 00 0f ae 1c 24 58 40 } //01 00 
		$a_01_2 = {83 e2 fe 69 c2 00 10 00 00 59 5a 66 0f 12 12 66 0f 7e d2 01 c2 } //01 00 
	condition:
		any of ($a_*)
 
}