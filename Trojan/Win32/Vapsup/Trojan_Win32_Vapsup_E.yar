
rule Trojan_Win32_Vapsup_E{
	meta:
		description = "Trojan:Win32/Vapsup.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d c4 83 c1 01 89 4d c4 8b 55 c4 3b 55 cc 73 31 8b 45 0c 50 e8 89 fd ff ff 83 c4 04 66 89 45 c0 0f b7 4d c0 81 f1 90 01 02 00 00 51 8d 4d d0 e8 1f 01 00 00 8b 55 f0 8b 45 0c 8d 0c 50 89 4d 0c eb be 90 00 } //01 00 
		$a_02_1 = {8b 55 f4 8b 45 08 0f b7 0c 50 83 f9 41 7c 90 01 01 8b 55 f4 8b 45 08 0f b7 0c 50 83 f9 46 7f 90 01 01 8b 55 f4 8b 45 08 0f b7 0c 50 83 e9 37 66 89 4d f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}