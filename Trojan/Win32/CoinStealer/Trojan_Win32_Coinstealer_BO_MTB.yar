
rule Trojan_Win32_Coinstealer_BO_MTB{
	meta:
		description = "Trojan:Win32/Coinstealer.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 19 30 03 43 83 ea 01 75 f5 8b 7d f8 8d 75 e4 83 e9 10 83 6d fc 01 89 4d 08 8b 4d f4 } //01 00 
		$a_01_1 = {8a 42 f3 32 c4 88 42 03 8a 42 f4 32 45 fd 88 42 04 8a 42 f5 32 c1 88 42 05 8a 42 f6 32 c5 43 88 42 06 83 c2 04 83 fb 2c 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}