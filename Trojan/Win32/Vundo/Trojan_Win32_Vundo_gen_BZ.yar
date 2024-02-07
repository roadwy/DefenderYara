
rule Trojan_Win32_Vundo_gen_BZ{
	meta:
		description = "Trojan:Win32/Vundo.gen!BZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 04 8a 89 45 90 01 01 8b 4d 90 01 01 8b 11 89 55 90 01 01 8b 45 90 01 01 33 45 90 01 01 8b 4d 90 01 01 33 01 90 00 } //01 00 
		$a_03_1 = {75 1a 8d 95 e8 fd ff ff 52 68 90 01 04 68 90 01 04 ff 15 90 00 } //01 00 
		$a_03_2 = {6a 3f 8b 85 6c f3 ff ff 50 ff 15 90 01 04 85 c0 75 0c c7 85 90 01 08 eb 0a 90 00 } //01 00 
		$a_01_3 = {78 32 5f 61 6c 69 76 65 5f 6d 75 74 65 78 } //00 00  x2_alive_mutex
	condition:
		any of ($a_*)
 
}