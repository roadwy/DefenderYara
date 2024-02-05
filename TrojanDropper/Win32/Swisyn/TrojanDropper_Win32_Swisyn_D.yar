
rule TrojanDropper_Win32_Swisyn_D{
	meta:
		description = "TrojanDropper:Win32/Swisyn.D,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 69 6e 73 69 64 65 74 6d } //02 00 
		$a_01_1 = {64 69 72 5f 77 61 74 63 68 2e 64 6c 6c } //03 00 
		$a_01_2 = {6b 6b 63 2d 31 32 6b 64 6d 71 64 6a } //04 00 
		$a_01_3 = {40 72 72 64 62 6e 71 4f 64 73 60 64 71 42 } //00 00 
	condition:
		any of ($a_*)
 
}