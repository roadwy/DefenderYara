
rule Backdoor_Win32_Small_BO{
	meta:
		description = "Backdoor:Win32/Small.BO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 45 78 70 6f 72 74 00 69 6d 70 6f 72 74 66 75 6e 63 00 } //01 00 
		$a_01_1 = {8b 46 14 8b 4e 18 2b c7 83 c4 0c 83 f9 10 89 46 14 72 02 8b 1b c6 04 03 00 5b } //01 00 
		$a_03_2 = {68 00 10 00 00 25 00 f0 ff ff 50 6a 00 6a 04 90 03 01 05 52 ff 35 90 01 04 ff 15 90 01 02 00 10 8b cf c1 e9 0c 81 e1 ff 03 00 00 8b 0c 88 f7 c1 01 00 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}