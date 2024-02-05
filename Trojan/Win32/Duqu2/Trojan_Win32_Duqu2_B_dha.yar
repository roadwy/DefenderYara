
rule Trojan_Win32_Duqu2_B_dha{
	meta:
		description = "Trojan:Win32/Duqu2.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {8d 16 8b 1a f7 db 0f cb c1 c3 03 0f cb 81 f3 } //01 00 
		$a_00_1 = {26 00 61 00 3d 00 6d 00 6f 00 75 00 73 00 65 00 } //01 00 
		$a_00_2 = {64 00 65 00 6c 00 61 00 79 00 65 00 64 00 2d 00 61 00 75 00 74 00 6f 00 } //01 00 
		$a_00_3 = {53 00 50 00 25 00 64 00 25 00 63 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 a9 
	condition:
		any of ($a_*)
 
}