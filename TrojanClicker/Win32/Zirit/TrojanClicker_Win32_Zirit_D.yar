
rule TrojanClicker_Win32_Zirit_D{
	meta:
		description = "TrojanClicker:Win32/Zirit.D,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //02 00 
		$a_01_1 = {66 69 72 73 74 63 6c 69 63 6b } //03 00 
		$a_01_2 = {6d 69 6e 63 6c 69 63 6b 74 69 6d 65 } //02 00 
		$a_01_3 = {65 78 65 63 75 72 6c } //02 00 
		$a_01_4 = {65 78 65 63 66 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}