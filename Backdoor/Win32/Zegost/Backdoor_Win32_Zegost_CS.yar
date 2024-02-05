
rule Backdoor_Win32_Zegost_CS{
	meta:
		description = "Backdoor:Win32/Zegost.CS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 25 ff ff 00 00 8b 4d 08 03 4d ec 8a 11 32 54 45 f8 8b 45 08 03 45 ec 88 10 66 8b 4d fc 66 83 c1 01 } //01 00 
		$a_01_1 = {c6 45 d2 33 c6 45 d3 32 c6 45 d4 2e c6 45 d5 64 c6 45 d6 6c c6 45 d7 6c c6 45 d8 00 8d 45 dc 50 8d 4d 90 51 ff 15 } //01 00 
		$a_01_2 = {00 5c 73 79 73 6c 6f 67 2e 64 61 74 00 } //01 00 
		$a_01_3 = {00 47 68 30 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}