
rule TrojanProxy_Win32_Koobface_gen_O{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 0a 32 45 10 88 01 49 ff 4d 08 75 f2 } //01 00 
		$a_01_1 = {8a 14 29 32 54 24 18 88 11 49 48 75 f3 } //01 00 
		$a_01_2 = {8a 04 0f 32 45 0c 88 01 49 ff 4d fc 75 f2 } //01 00 
		$a_01_3 = {62 74 77 5f 6f 6b 6f 2e 64 6c 6c } //00 00  btw_oko.dll
	condition:
		any of ($a_*)
 
}