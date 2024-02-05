
rule Trojan_Win32_CrimSon_J_ibt{
	meta:
		description = "Trojan:Win32/CrimSon.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 4b 52 50 43 4f 4e } //01 00 
		$a_00_1 = {64 62 73 72 75 61 6c 62 6d 6c 6f 61 64 4d 65 } //01 00 
		$a_02_2 = {70 17 8d 05 00 00 01 13 90 01 01 11 90 01 01 16 06 a2 00 11 90 01 01 14 14 14 28 90 01 01 00 00 0a 28 0a 00 00 0a 13 90 00 } //01 00 
		$a_02_3 = {02 72 b9 00 00 70 17 8d 90 01 01 00 00 01 0a 06 16 1f 7c 9d 06 6f 61 00 00 0a 16 9a 7d 0d 00 00 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}