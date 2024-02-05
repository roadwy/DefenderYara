
rule Trojan_Win32_TrickBot_KVP_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.KVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 } //02 00 
		$a_00_1 = {8b 44 24 14 5b 8d 0c 06 8b c6 f7 f3 8b 44 24 0c 8a 04 02 30 01 } //02 00 
		$a_00_2 = {8b 45 f0 6a 26 33 d2 5f 03 c8 f7 f7 8a 44 15 9c 30 01 } //01 00 
		$a_02_3 = {69 c0 fd 43 03 00 83 ec 50 56 a3 90 09 05 00 a1 90 00 } //01 00 
		$a_02_4 = {30 04 33 81 ff 1e 10 00 00 75 90 09 05 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}