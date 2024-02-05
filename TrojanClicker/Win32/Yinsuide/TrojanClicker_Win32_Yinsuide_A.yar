
rule TrojanClicker_Win32_Yinsuide_A{
	meta:
		description = "TrojanClicker:Win32/Yinsuide.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 74 00 72 00 6c 00 2e 00 73 00 68 00 75 00 69 00 64 00 75 00 6e 00 2e 00 6f 00 72 00 67 00 2f 00 63 00 66 00 67 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_1 = {2f 00 74 00 6e 00 20 00 22 00 59 00 52 00 54 00 65 00 73 00 74 00 54 00 61 00 73 00 6b 00 22 00 20 00 2f 00 74 00 72 00 } //01 00 
		$a_01_2 = {5c 75 73 65 72 73 5c 79 72 2e 6e 65 74 5c 64 65 73 6b 74 6f 70 5c } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}