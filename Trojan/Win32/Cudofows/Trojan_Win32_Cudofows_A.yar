
rule Trojan_Win32_Cudofows_A{
	meta:
		description = "Trojan:Win32/Cudofows.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b c6 83 c0 fb 88 46 01 8b c8 8b d0 c1 e8 10 c1 e9 18 88 46 03 c1 ea 08 8d 44 24 08 50 88 4e 04 c6 06 e9 88 56 02 } //01 00 
		$a_03_1 = {6a 28 8d 94 24 60 01 00 00 52 56 ff 15 90 01 04 68 03 01 00 00 8d 44 24 55 56 50 c6 44 24 5c 00 90 00 } //01 00 
		$a_03_2 = {6a 23 8d 84 24 5c 01 00 00 50 6a 00 ff 90 01 05 68 03 01 00 00 8d 4c 24 55 6a 00 51 c6 44 24 5c 00 e8 90 00 } //02 00 
		$a_01_3 = {0f b6 14 32 32 14 2f 47 83 6c 24 14 01 88 57 ff 75 a3 } //00 00 
	condition:
		any of ($a_*)
 
}