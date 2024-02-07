
rule Trojan_Win32_Tarifarch_U{
	meta:
		description = "Trojan:Win32/Tarifarch.U,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 6f 6f 77 69 6f 30 39 30 39 70 71 69 77 65 00 } //01 00 
		$a_01_1 = {6f 6f 61 73 6f 6b 39 38 30 39 61 73 6f 6b 64 00 } //01 00  潯獡歯㠹㤰獡歯d
		$a_03_2 = {05 08 10 11 c0 2b 45 f4 2d 00 10 11 00 ff d0 0b c0 0f 84 9b 00 00 00 89 45 f8 8b f8 8b 75 fc 8b 0d 00 30 40 00 f3 a4 ff 35 00 30 40 00 ff 75 f8 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_3 = {8b 45 08 05 90 01 02 00 00 2d 90 01 01 00 00 c0 83 c0 90 01 01 03 45 f4 89 45 fc 6a 40 68 00 30 00 00 ff 35 00 30 40 00 33 c0 50 a1 90 01 02 40 00 05 08 10 11 c0 2b 45 f4 2d 00 10 11 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}