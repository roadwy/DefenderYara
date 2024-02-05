
rule Trojan_Win32_Dogrobot_H{
	meta:
		description = "Trojan:Win32/Dogrobot.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f5 61 81 7d e0 4b e1 22 00 0f 85 } //01 00 
		$a_01_1 = {39 41 08 77 09 c7 45 e4 0d 00 00 c0 eb } //01 00 
		$a_00_2 = {5c 00 3f 00 3f 00 5c 00 78 00 7a 00 77 00 69 00 6e 00 44 00 4f 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}