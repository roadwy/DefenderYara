
rule Backdoor_Win32_Zegost_CH_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 11 80 ea 90 01 01 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 90 01 01 8b 45 fc 03 45 f8 88 10 eb 90 00 } //01 00 
		$a_01_1 = {c6 45 f5 67 c6 45 f6 75 c6 45 f7 65 c6 45 f8 73 c6 45 f9 74 c6 45 fa 20 c6 45 fb 2f c6 45 fc 61 c6 45 fd 64 c6 45 fe 64 c6 45 ff 00 6a 00 8d 45 a0 50 ff 15 } //01 00 
		$a_03_2 = {52 c6 85 7d 90 01 03 69 c6 85 7e 90 01 03 73 c6 85 7f 90 01 03 69 c6 85 80 90 01 03 6e c6 85 81 90 01 03 67 c6 85 82 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}