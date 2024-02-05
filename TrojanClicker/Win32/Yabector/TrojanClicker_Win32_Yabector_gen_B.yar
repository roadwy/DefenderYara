
rule TrojanClicker_Win32_Yabector_gen_B{
	meta:
		description = "TrojanClicker:Win32/Yabector.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 f0 b8 90 01 04 e8 90 01 04 6a 01 6a 00 6a 00 68 90 01 04 68 90 01 04 a1 90 01 04 8b 00 8b 40 30 50 e8 90 01 04 e8 90 01 04 90 02 03 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f 90 01 04 2f 90 02 03 6f 70 65 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}