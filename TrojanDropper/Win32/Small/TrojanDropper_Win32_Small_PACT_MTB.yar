
rule TrojanDropper_Win32_Small_PACT_MTB{
	meta:
		description = "TrojanDropper:Win32/Small.PACT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 46 04 8a c8 80 e1 01 0f b6 7e 05 fe c9 f6 d9 1b c9 24 08 2c 08 41 f6 d8 89 4c 24 18 1b c0 40 89 44 24 10 0f b6 46 06 c1 e7 08 03 f8 0f b6 46 07 c1 e7 08 03 f8 } //00 00 
	condition:
		any of ($a_*)
 
}