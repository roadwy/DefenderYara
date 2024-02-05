
rule TrojanClicker_Win32_Popagerty_A{
	meta:
		description = "TrojanClicker:Win32/Popagerty.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {70 6f 70 75 70 67 75 69 64 65 5c 64 61 74 61 2e 64 62 } //02 00 
		$a_01_1 = {63 6f 75 6e 74 65 72 2e 70 6f 70 2d 75 70 67 75 69 64 65 2e 63 6f 6d } //02 00 
		$a_01_2 = {70 6f 70 75 70 67 75 69 64 65 5c 73 6f 75 72 63 65 5c 4d 61 69 6e 55 2e 70 61 73 } //01 00 
		$a_01_3 = {69 6c 69 6b 65 63 6c 69 63 6b 2e 63 6f 6d 2f 74 72 61 63 6b 2f 63 6c 69 63 6b 2e 70 68 70 } //01 00 
		$a_01_4 = {70 6f 70 75 70 67 75 69 64 65 5f 30 32 } //00 00 
	condition:
		any of ($a_*)
 
}