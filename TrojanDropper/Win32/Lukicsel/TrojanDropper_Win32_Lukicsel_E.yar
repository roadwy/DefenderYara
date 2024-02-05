
rule TrojanDropper_Win32_Lukicsel_E{
	meta:
		description = "TrojanDropper:Win32/Lukicsel.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 e8 90 01 04 85 c0 74 f3 8b 45 f8 8b 55 fc 0f ac d0 02 c1 ea 02 81 e0 01 00 00 00 33 d2 81 f0 01 00 00 00 81 f2 00 00 00 00 83 fa 00 75 cd 83 f8 01 75 c8 e8 90 01 01 ff ff ff 32 06 88 07 46 47 4b 75 ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}