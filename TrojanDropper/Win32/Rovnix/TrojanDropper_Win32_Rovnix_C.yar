
rule TrojanDropper_Win32_Rovnix_C{
	meta:
		description = "TrojanDropper:Win32/Rovnix.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 00 42 00 52 00 00 00 5c 00 3f 00 3f 00 5c 00 50 00 48 00 59 00 53 00 49 00 43 00 41 00 4c 00 44 00 52 00 49 00 56 00 45 00 30 00 00 00 } //01 00 
		$a_02_1 = {0f b7 88 fe 01 00 00 81 f9 55 aa 00 00 74 05 e9 90 01 04 8b 55 90 01 01 81 c2 be 01 00 00 89 55 90 01 01 c7 45 90 01 01 00 00 00 00 83 7d 90 01 01 04 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}