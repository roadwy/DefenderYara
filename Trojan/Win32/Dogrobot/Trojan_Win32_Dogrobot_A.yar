
rule Trojan_Win32_Dogrobot_A{
	meta:
		description = "Trojan:Win32/Dogrobot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 4c 82 fc 8b 0d 90 01 04 3b c1 7c e2 a1 90 01 04 0f 22 c0 fb c3 90 00 } //02 00 
		$a_01_1 = {66 c7 45 fc e3 03 66 89 45 f8 66 89 45 fa ff 5d f8 8b c4 8b 64 24 04 } //02 00 
		$a_03_2 = {6a 08 52 6a 26 ff 15 90 01 04 85 c0 7c 16 e8 90 01 02 00 00 85 c0 74 0d 68 90 01 04 e8 90 01 01 00 00 00 90 00 } //01 00 
		$a_00_3 = {00 74 61 73 6b 6b 69 6c 6c 00 } //01 00 
		$a_00_4 = {2f 66 20 2f 69 6d 20 61 76 70 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}