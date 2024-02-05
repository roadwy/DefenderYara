
rule Backdoor_Win32_Zegost_BU{
	meta:
		description = "Backdoor:Win32/Zegost.BU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 c4 80 74 90 01 01 6a 14 ff 15 90 01 03 00 66 85 c0 74 90 01 01 83 ff ff 7e 90 01 01 83 fe 40 7e 90 01 01 83 fe 5b 7d 10 90 00 } //01 00 
		$a_00_1 = {68 04 01 00 00 50 c6 44 24 18 5c c6 44 24 1a 75 c6 44 24 1b 72 c6 44 24 1c 6c c6 44 24 1e 67 c6 44 24 1f 2e } //01 00 
		$a_02_2 = {8a 08 83 c1 fe 83 f9 0d 0f 87 90 01 02 00 00 ff 24 8d 90 01 02 40 00 40 8b ce 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}