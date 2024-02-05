
rule TrojanClicker_Win32_Nomush_A{
	meta:
		description = "TrojanClicker:Win32/Nomush.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 74 72 6c 4b 65 79 00 44 6f 77 } //01 00 
		$a_01_1 = {2f 6e 6f 63 61 73 68 2f 75 72 6c 73 2e 70 68 70 00 } //01 00 
		$a_01_2 = {6e 00 6f 00 63 00 61 00 73 00 68 00 65 00 6d 00 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}