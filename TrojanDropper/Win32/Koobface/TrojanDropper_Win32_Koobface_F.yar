
rule TrojanDropper_Win32_Koobface_F{
	meta:
		description = "TrojanDropper:Win32/Koobface.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6e 73 62 6c 6f 63 6b 65 72 5c 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 46 69 6c 74 65 72 2e 70 64 62 00 } //01 00 
		$a_01_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 43 00 74 00 72 00 6c 00 } //01 00 
		$a_01_2 = {73 25 73 25 73 5c 64 72 69 25 73 25 73 54 45 25 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}